/**
 * PcapParser written in java
 * Based on the documentation found: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/
 *
 * @author raphaelgiaquinto
 */

import java.io.*;
import java.nio.*;

enum PcapFileFormat {
    BIG_ENDIAN_MICRO_SECONDS,
    LITTLE_ENDIAN_MICRO_SECONDS,
    BIG_ENDIAN_NANO_SECONDS,
    LITTLE_ENDIAN_NANO_SECONDS
}

enum PcapEthernetType {
    ARP, IPV4, IPV6,
}

enum PcapIPV4Protocol {
    TCP, UDP, ICMP,
}

enum PcapIPV6Protocol {
    TCP, UDP, ICMPv6,
}
record PcapVersion(int majorVersion, int minorVersion) {}

record LinkTypeAndAdditionalInfo(int fcsLen, int r, int p, int reserved3, int linkType) {}

class PcapParserException extends RuntimeException {
    public PcapParserException(String message) {
        super("oups ! a PcapParserException occurred: " + message);
    }
}

void main(String[] args) {

    if (args.length != 1) {
        IO.println("Usage: java PcapParser <.pcap file>");
        System.exit(1);
    }

    var pcapFile = args[0];

    if (!pcapFile.endsWith(".pcap")) {
        IO.println("Error: PCAP file must have a .pcap extension");
        System.exit(1);
    }

    try (var pcapStream = new FileInputStream(pcapFile)) {
        var bytes = ByteBuffer.wrap(pcapStream.readAllBytes());
        if (bytes.remaining() < 24) {
            IO.println("Error: PCAP file is too small, a header must be present and weigh at least 24 bytes");
            System.exit(1);
        }
        //the magic number is on the first 4 bytes of the header (header is 24 bytes)
        var magicNumberBuffer = bytes.slice(0, 4);
        var pcapFileFormat = getPcapFileFormat(magicNumberBuffer);
        if (pcapFileFormat == null) {
            IO.println("Error: PCAP file is not in a supported format");
            System.exit(1);
        }
        IO.println("Pcap file format: " + pcapFileFormat);
        //the versions are on the next 4 bytes after the magic number
        var versionsBuffer = bytes.slice(4, 4);
        var pcapVersions = getPcapVersions(pcapFileFormat, versionsBuffer);
        IO.println("Pcap versions: " + pcapVersions);
        //the snap length is on the next 4 bytes after reserved1 and reserved2 sections (4 bytes each)
        var snapLenBuffer = bytes.slice(16, 4);
        var snapLen = getSnapLen(pcapFileFormat, snapLenBuffer);
        IO.println("Snap length: " + snapLen + " (max captured packet size in bytes)");
        //the linktype is on the next 4 bytes after the snap length section
        var linkTypeBuffer = bytes.slice(20, 4);
        var linkTypeAndAdditionalInfo = getLinkTypeAndAdditionalInformation(pcapFileFormat, linkTypeBuffer);
        IO.println("Link and additional information: " + linkTypeAndAdditionalInfo);
        if (linkTypeAndAdditionalInfo.linkType != 1) {
            IO.println("Error: link type must be 1 (Ethernet)");
            System.exit(1);
        }
        //all the next bytes packets data to parse
        var packetDataBuffer = bytes.slice(24, bytes.remaining() - 24);
        IO.println("Packet data:" + packetDataBuffer.remaining());
        readPackets(pcapFileFormat, packetDataBuffer);
    } catch (IOException e) {
        IO.println("Error reading PCAP file: " + e.getMessage());
        System.exit(1);
    }
}

void readPacket(int count, int timestampSeconds, int timestampMicroSeconds, int capturedLength, int packetLength, ByteBuffer packetData) {
    var template = """
    Packet [%d]
    ________________________________________________________
        Timestamp seconds:      %d
        Timestamp microseconds: %d
        Captured length:        %d
        Packet length:          %d bytes
        Ethernet:               [ dest MAC: %s | src MAC: %s | type: %s ]
    """;
    var destMAC = new byte[6];
    var srcMAC = new byte[6];
    packetData.get(destMAC);
    packetData.get(srcMAC);
    packetData.order(ByteOrder.BIG_ENDIAN);
    var ethernetType = getPcapEthernetType(packetData.getShort() & 0xFFFF);
    IO.println(
            String.format(
                    template,
                    count,
                    timestampSeconds,
                    timestampMicroSeconds,
                    capturedLength,
                    packetLength,
                    formatMacAddress(destMAC),
                    formatMacAddress(srcMAC),
                    ethernetType
            )
    );
    switch (ethernetType) {
        case IPV4 -> parsePacketIPV4(packetData);
        case ARP -> parsePacketARP(packetData);
        case IPV6 -> parsePacketIPV6(packetData);
        default -> IO.println("Error: unknown ethernet type: " + ethernetType);
    }
}

/**
 * Parses the ARP packet data with the help of the packetData buffer with it cursor positioned at the start of the packet (after ethernet type)
 * @param packetData
 */
void parsePacketARP(ByteBuffer packetData) {
    packetData.order(ByteOrder.BIG_ENDIAN);
    packetData.position(packetData.position() + 6);
    var opcode = packetData.getShort() & 0xFF;
    var operation = opcode == 1 ? "Request" : "Reply";
    var senderMac = new byte[6];
    packetData.get(senderMac);
    var senderIp = new byte[4];
    packetData.get(senderIp);
    var targetMac = new byte[6];
    packetData.get(targetMac);
    var targetIp = new byte[4];
    packetData.get(targetIp);
    String template = """
        ARP data: [ operation: %s | sender MAC: %s | sender IP: %s | target MAC: %s | target IP: %s ]
    """;

    System.out.println(String.format(template, operation, formatMacAddress(senderMac), formatIpAddress(senderIp), formatMacAddress(targetMac), formatIpAddress(targetIp)));
}

/**
 * Parses the IPV4 packet data with the help of the packetData buffer
 * @param packetData
 */
void parsePacketIPV4(ByteBuffer packetData) {
    packetData.order(ByteOrder.BIG_ENDIAN);

    // first byte : version (4 bits) and ihl (4 bits)
    byte versionAndIHL = packetData.get();
    var ihl = (versionAndIHL & 0x0F); // keep 4 of right hand byte
    int headerLengthBytes = ihl * 4;

    // skip the type of service (1 byte)
    packetData.get();

    var totalLength = packetData.getShort() & 0xFFFF;

    //skip the identification (2 bytes)
    packetData.getShort();

    //flags (3 bits) and fragment offset (13 bits)
    var flagsAndOffset = packetData.getShort();
    var flags = (flagsAndOffset >>> 13) & 0x07;
    var fragmentOffset = flagsAndOffset & 0x1FFF;

    //ttl (8 bits) and protocol (8 bits)
    var ttl = packetData.get() & 0xFF;
    var protocol = packetData.get() & 0xFF;
    var ipv4Protocol = getPcapIPV4Protocol(protocol);

    //skip checksum (2 bytes)
    packetData.getShort();

    //IP address src and dest
    var srcIp = new byte[4];
    var dstIp = new byte[4];
    packetData.get(srcIp);
    packetData.get(dstIp);

    //options managed by the IHL field (20 bytes max)
    if (headerLengthBytes > 20) {
        int optionsLength = headerLengthBytes - 20;
        packetData.position(packetData.position() + optionsLength);
    }

    String template = """
        IPv4 data [
            src IP: %s | dest IP: %s
            TTL:    %d | protocol:    %s | total length: %d
            IHL:    %d bytes | flags: %d | fragment offset: %d
        ]
    """;

    IO.println(String.format(template,
            formatIpAddress(srcIp), formatIpAddress(dstIp),
            ttl, ipv4Protocol, totalLength,
            headerLengthBytes, flags, fragmentOffset));

    /*
        packetData.position() is properly positioned at the start of the packet data
        now we can parse the packet data based on the protocol
    */
    switch (ipv4Protocol) {
        case TCP ->  parseTCPPacket(packetData);
        case UDP -> parseUDPPacket(packetData);
        case ICMP -> {
            return;
        }
    }
}

/**
 * Parses the IPv6 packet data using the packetData buffer
 * @param packetData
 */
void parsePacketIPV6(ByteBuffer packetData) {
    packetData.order(ByteOrder.BIG_ENDIAN);

    //skip 4 bytes (version, traffic class, flow label)
    packetData.getInt();

    //payload length (2 bytes)
    int payloadLength = packetData.getShort() & 0xFFFF;

    //next header (1 byte)
    int nextHeader = packetData.get() & 0xFF;

    //hop limit (1 byte)
    int hopLimit = packetData.get() & 0xFF;

    //IP src and dest (16 bytes each)
    byte[] srcIpv6 = new byte[16];
    byte[] dstIpv6 = new byte[16];
    packetData.get(srcIpv6);
    packetData.get(dstIpv6);
    var protocol = getPcapIPV6Protocol(nextHeader);


    var template = """
        IPv6 data [
            IP src:                %s |    IP dest: %s
            next header:           %s      (%d)
            hop limit:             %d
            payload length:        %d bytes
        ]
    """;

    IO.println(String.format(template,
            formatIpv6Address(srcIpv6),
            formatIpv6Address(dstIpv6),
            protocol, nextHeader,
            hopLimit,
            payloadLength));
}

/**
 * Parse TCP packet data (it is a bit more complex than the IPV4 packet, because it has a header with 20 bytes and a payload with variable length)
 * It is REALLY MORE challenging than UDP to parse :(
 * @param packetData
 */
void parseTCPPacket(ByteBuffer packetData) {
    packetData.order(ByteOrder.BIG_ENDIAN);
    var startPosition = packetData.position();

    //ports (2 bytes each)
    var srcPort = packetData.getShort() & 0xFFFF;
    var dstPort = packetData.getShort() & 0xFFFF;

    //seq and ack (32 bits each)
    var seq = packetData.getInt() & 0xFFFFFFFFL;
    var ack = packetData.getInt() & 0xFFFFFFFFL;

    //data offset length of the header (4 bits)
    var offsetByte = packetData.get();
    var dataOffset = (offsetByte >> 4) & 0x0F;
    var headerLengthBytes = dataOffset * 4;

    // flags (1 byte)
    var flagsByte = packetData.get();
    var urg = (flagsByte & 0x20) != 0;
    var ackF = (flagsByte & 0x10) != 0;
    var psh = (flagsByte & 0x08) != 0;
    var rst = (flagsByte & 0x04) != 0;
    var syn = (flagsByte & 0x02) != 0;
    var fin = (flagsByte & 0x01) != 0;

    //window
    var window = packetData.getShort() & 0xFFFF;

    //skip options, go to the end of the TCP header
    packetData.position(startPosition + headerLengthBytes);

    var flags = String.format("SYN: %b | ACK :%b | FIN :%b | RST :%b | PSH :%b | URG: %b", syn, ackF, fin, rst, psh, urg);

    IO.println("""
        TCP data [
            ports:    %d -> %d
            seq:      %d
            ack:      %d
            Flags:    %s
            window:   %d | header length: %d bytes
        ]
    """.formatted(srcPort, dstPort, seq, ack, flags, window, headerLengthBytes));

    //now, this is the payload data
    if (packetData.remaining() > 0) {

    }
}

/**
 * Parses the UDP packet data with the help of the packetData buffer
 * EASY TO PARSE :D
 * @param packetData
 */
void parseUDPPacket(ByteBuffer packetData) {
    packetData.order(ByteOrder.BIG_ENDIAN);

    //ports (2 bytes each)
    var srcPort = packetData.getShort() & 0xFFFF;
    var dstPort = packetData.getShort() & 0xFFFF;

    //length (2 bytes)
    var length = packetData.getShort() & 0xFFFF;

    //skip checksum (2 bytes)
    packetData.getShort();

    IO.println(String.format("""
        UDP data [
            ports:  %d -> %d
            length: %d bytes
        ]
    """, srcPort, dstPort, length));

    //now this is the payload data
    if (packetData.remaining() > 0) {

    }
}
String formatIpAddress(byte[] ipAddress) {
    return String.format("%d.%d.%d.%d", ipAddress[0] & 0xFF, ipAddress[1] & 0xFF, ipAddress[2] & 0xFF, ipAddress[3] & 0xFF);
}

String formatIpv6Address(byte[] ipv6Address) {
    return String.format("%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X", ipv6Address[0], ipv6Address[1], ipv6Address[2], ipv6Address[3], ipv6Address[4], ipv6Address[5], ipv6Address[6], ipv6Address[7]);
}

String formatMacAddress(byte[] macAddress) {
    return String.format("%02X:%02X:%02X:%02X:%02X:%02X", macAddress[0], macAddress[1], macAddress[2], macAddress[3], macAddress[4], macAddress[5]);
}

void readPackets(PcapFileFormat pcapFileFormat, ByteBuffer packetDataBuffer) {
    switch (pcapFileFormat) {
        case BIG_ENDIAN_MICRO_SECONDS, BIG_ENDIAN_NANO_SECONDS:
            packetDataBuffer.order(ByteOrder.BIG_ENDIAN);
            break;
        case LITTLE_ENDIAN_MICRO_SECONDS, LITTLE_ENDIAN_NANO_SECONDS:
            packetDataBuffer.order(ByteOrder.LITTLE_ENDIAN);
            break;
    }
    var packetCount = 0;
    while (packetDataBuffer.remaining() >= 16) {
        var timestampSeconds = packetDataBuffer.getInt();
        var timestampMicroSeconds = packetDataBuffer.getInt();
        var capturedLength = packetDataBuffer.getInt();
        var packetLength = packetDataBuffer.getInt();
        var packetData = packetDataBuffer.slice(packetDataBuffer.position(), capturedLength);
        packetData.order(packetDataBuffer.order());
        packetDataBuffer.position(packetDataBuffer.position() + capturedLength);
        readPacket(packetCount, timestampSeconds, timestampMicroSeconds, capturedLength, packetLength, packetData);
        packetCount++;
    }
    IO.println("Number of packets read: " + packetCount);
}

/**
 * Extracts the pcap file format from the magic number
 *
 * @param magicNumberBuffer byte buffer containing the magic number on 4 bytes
 * @return the pcap file format or null if the magic number is not recognized
 */
PcapFileFormat getPcapFileFormat(ByteBuffer magicNumberBuffer) {
    if (magicNumberBuffer.remaining() < 4) {
        throw new RuntimeException("Magic number buffer must contain at least 4 bytes");
    }
    magicNumberBuffer.order(ByteOrder.BIG_ENDIAN);
    int magicNumber = magicNumberBuffer.getInt();
    if (magicNumber == 0xA1B2C3D4) {
        return PcapFileFormat.BIG_ENDIAN_MICRO_SECONDS;
    } else if (magicNumber == 0xA1B23C4D) {
        return PcapFileFormat.BIG_ENDIAN_NANO_SECONDS;
    } else {
        magicNumberBuffer.order(ByteOrder.LITTLE_ENDIAN);
        magicNumberBuffer.position(0);
        magicNumber = magicNumberBuffer.getInt();
        if (magicNumber == 0xA1B2C3D4) {
            return PcapFileFormat.LITTLE_ENDIAN_MICRO_SECONDS;
        } else if (magicNumber == 0xA1B23C4D) {
            return PcapFileFormat.LITTLE_ENDIAN_NANO_SECONDS;
        } else {
            return null;
        }
    }
}

/**
 * Returns the ethernet type from the extracted packet data
 * @param ethernetType
 * @return the ethernet type or null if the ethernet type is not recognized
 */
PcapEthernetType getPcapEthernetType(int ethernetType) {
    if (ethernetType == 0x0800) {
        return PcapEthernetType.IPV4;
    }
    if (ethernetType == 0x86DD) {
        return PcapEthernetType.IPV6;
    }
    if (ethernetType == 0x0806) {
        return PcapEthernetType.ARP;
    }
    return null;
}

PcapIPV4Protocol getPcapIPV4Protocol(int protocol) {
    return switch (protocol) {
        case 1 -> PcapIPV4Protocol.ICMP;
        case 6 -> PcapIPV4Protocol.TCP;
        case 17 -> PcapIPV4Protocol.UDP;
        default -> null;
    };
}

PcapIPV6Protocol getPcapIPV6Protocol(int protocol) {
    return switch (protocol) {
        case 6 -> PcapIPV6Protocol.TCP;
        case 17 -> PcapIPV6Protocol.UDP;
        case 58 -> PcapIPV6Protocol.ICMPv6;
        default -> null;
    };
}
/**
 * Extracts the major and minor versions from the pcap header
 *
 * @param pcapFileFormat the pcap file format extracted from the magic number
 * @param versionsBuffer byte buffer containing the versions on 4 bytes
 * @return the major and minor versions as record
 */

PcapVersion getPcapVersions(PcapFileFormat pcapFileFormat, ByteBuffer versionsBuffer) {
    if (versionsBuffer.remaining() != 4) {
        throw new PcapParserException("Versions buffer must contain 4 bytes");
    }
    switch (pcapFileFormat) {
        case BIG_ENDIAN_MICRO_SECONDS, BIG_ENDIAN_NANO_SECONDS:
            versionsBuffer.order(ByteOrder.BIG_ENDIAN);
            break;
        case LITTLE_ENDIAN_MICRO_SECONDS, LITTLE_ENDIAN_NANO_SECONDS:
            versionsBuffer.order(ByteOrder.LITTLE_ENDIAN);
            break;
    }
    var majorVersion = versionsBuffer.getShort(); //a short is 2 bytes
    var minorVersion = versionsBuffer.getShort(); //grab the next 2 bytes
    return new PcapVersion(majorVersion, minorVersion);
}

/**
 * Returns the snap length from the pcap header
 * the snap length is the maximum number of bytes captured in each packet
 *
 * @param pcapFileFormat
 * @param snapLenBuffer
 * @return the snap length
 */
int getSnapLen(PcapFileFormat pcapFileFormat, ByteBuffer snapLenBuffer) {
    if (snapLenBuffer.remaining() != 4) {
        throw new PcapParserException("Snap len buffer must contain 4 bytes");
    }
    switch (pcapFileFormat) {
        case BIG_ENDIAN_MICRO_SECONDS, BIG_ENDIAN_NANO_SECONDS:
            snapLenBuffer.order(ByteOrder.BIG_ENDIAN);
            break;
        case LITTLE_ENDIAN_MICRO_SECONDS, LITTLE_ENDIAN_NANO_SECONDS:
            snapLenBuffer.order(ByteOrder.LITTLE_ENDIAN);
            break;
    }
    return snapLenBuffer.getInt();
}

/**
 * Returns the linktype and additional information from the pcap header
 * the linktype is the type of the network layer protocol
 *
 * @param pcapFileFormat
 * @param linkTypeAdditionalInfoBuffer
 * @return the linktype and additional information as record
 */
LinkTypeAndAdditionalInfo getLinkTypeAndAdditionalInformation(PcapFileFormat pcapFileFormat, ByteBuffer linkTypeAdditionalInfoBuffer) {
    if (linkTypeAdditionalInfoBuffer.remaining() != 4) {
        throw new PcapParserException("Link type buffer must contain 4 bytes");
    }
    switch (pcapFileFormat) {
        case BIG_ENDIAN_MICRO_SECONDS, BIG_ENDIAN_NANO_SECONDS:
            linkTypeAdditionalInfoBuffer.order(ByteOrder.BIG_ENDIAN);
            break;
        case LITTLE_ENDIAN_MICRO_SECONDS, LITTLE_ENDIAN_NANO_SECONDS:
            linkTypeAdditionalInfoBuffer.order(ByteOrder.LITTLE_ENDIAN);
            break;
    }
    var block32bits = linkTypeAdditionalInfoBuffer.getInt();
    var fcsLen = (block32bits >>> 28) & 0x0F;
    var r = (block32bits >>> 27) & 0x01;
    var p = (block32bits >>> 26) & 0x01;
    var reserved3 = (block32bits >>> 16) & 0x03FF;
    var linkType = (block32bits & 0xFFFF);
    return new LinkTypeAndAdditionalInfo(fcsLen, r, p, reserved3, linkType);
}