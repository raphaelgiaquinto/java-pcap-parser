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

    if (args.length < 1) {
        IO.println("Usage: java PcapParser <.pcap file> --proto<tcp|udp|dns|arp|icmp|quic> (optional)");
        System.exit(1);
    }

    var pcapFile = args[0];
    List<String> protocolFilters = new ArrayList<>();
    for (var i = 1; i < args.length; i++) {
        var arg = args[i];
        if (arg.startsWith("--proto=")) {
            var protocol = arg.substring(8).toLowerCase();
            if (Set.of("tcp", "udp", "dns", "arp", "icmp", "quic").contains(protocol)) {
                protocolFilters.add(protocol);
                IO.println("Protocol filter set to: " + protocol);
            } else {
                IO.println("Error: unknown protocol filter: " + protocol);
                System.exit(1);
            }
        }
    }
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
        readPackets(pcapFileFormat, packetDataBuffer, protocolFilters);
    } catch (IOException e) {
        IO.println("Error reading PCAP file: " + e.getMessage());
        System.exit(1);
    }
}

void readPacket(int count, int timestampSeconds, int timestampMicroSeconds, int capturedLength, int packetLength, ByteBuffer packetData, List<String> protocolFilters) {
    var template = "Packet [%d] | timestamp s: %d | timestamp µs: %d | captured length: %d | packet length: %d bytes | ethernet : [ dest MAC: %s | src MAC: %s | type: %s ]";
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
        case IPV4 -> parsePacketIPV4(packetData, protocolFilters);
        case ARP -> parsePacketARP(packetData, protocolFilters);
        case IPV6 -> parsePacketIPV6(packetData, protocolFilters);
        default -> IO.println("Error: unknown ethernet type: " + ethernetType);
    }
    IO.println(String.format("End of packet %d", count));
}

/**
 * Parses the ARP packet data with the help of the packetData buffer with it cursor positioned at the start of the packet (after ethernet type)
 * @param packetData
 * @param protocolFilters
 */
void parsePacketARP(ByteBuffer packetData, List<String> protocolFilters) {
    if (!protocolFilters.contains("arp") && !protocolFilters.isEmpty()) {
        return;
    }
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
    String template = "ARP data: [ operation: %s | sender MAC: %s | sender IP: %s | target MAC: %s | target IP: %s ]";

    IO.println(String.format(template, operation, formatMacAddress(senderMac), formatIpAddress(senderIp), formatMacAddress(targetMac), formatIpAddress(targetIp)));
}

/**
 * Parses the IPV4 packet data with the help of the packetData buffer
 * @param packetData
 * @param protocolFilters
 */
void parsePacketIPV4(ByteBuffer packetData, List<String> protocolFilters) {
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

    String template = "IPv4 data [ src IP: %s | dest IP: %s | TTL: %d | protocol: %s | total length: %d | IHL: %d bytes | flags: %d | fragment offset: %d ]";

    IO.println(String.format(template,
            formatIpAddress(srcIp), formatIpAddress(dstIp),
            ttl, ipv4Protocol, totalLength,
            headerLengthBytes, flags, fragmentOffset));

    /*
        packetData.position() is properly positioned at the start of the packet data
        now we can parse the packet data based on the protocol
    */
    switch (ipv4Protocol) {
        case TCP ->  parseTCPPacket(packetData, protocolFilters);
        case UDP -> parseUDPPacket(packetData, protocolFilters);
        case ICMP -> parseICMPPacketV4(packetData, protocolFilters);
    }
}

/**
 * Parses the IPv6 packet data using the packetData buffer
 * @param packetData
 * @param protocolFilters
 */
void parsePacketIPV6(ByteBuffer packetData, List<String> protocolFilters) {
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


    var template = "IPv6 data [ IP src: %s | IP dest: %s | next header: %s (%d) | hop limit: %d | payload length: %d bytes ]";

    IO.println(String.format(template,
            formatIpv6Address(srcIpv6),
            formatIpv6Address(dstIpv6),
            protocol, nextHeader,
            hopLimit,
            payloadLength));

    if (protocol == PcapIPV6Protocol.ICMPv6 && (protocolFilters.contains("icmp") || protocolFilters.isEmpty())) {
        parseICMPPacketV6(packetData);
    }
}

/**
 * Parse TCP packet data (it is a bit more complex than the IPV4 packet, because it has a header with 20 bytes and a payload with variable length)
 * It is REALLY MORE challenging than UDP to parse :(
 * @param packetData
 * @param protocolFilters
 */
void parseTCPPacket(ByteBuffer packetData, List<String> protocolFilters) {
    if (!protocolFilters.contains("tcp") && !protocolFilters.isEmpty()) {
        return;
    }
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

    IO.println("TCP data [ ports: %d -> %d | seq: %d | ack: %d | flags: %s | window: %d | header length: %d bytes ]".formatted(srcPort, dstPort, seq, ack, flags, window, headerLengthBytes));

    //now, this is the payload data
    if (packetData.remaining() > 0) {
        parseDataPayload(packetData);
    }
}

/**
 * Parses the UDP packet data with the help of the packetData buffer
 * EASY TO PARSE :D
 * @param packetData
 * @param protocolFilters
 */
void parseUDPPacket(ByteBuffer packetData, List<String> protocolFilters) {
    if (!protocolFilters.contains("udp") && !protocolFilters.isEmpty()) {
        return;
    }
    packetData.order(ByteOrder.BIG_ENDIAN);

    //ports (2 bytes each)
    var srcPort = packetData.getShort() & 0xFFFF;
    var dstPort = packetData.getShort() & 0xFFFF;

    //length (2 bytes)
    var length = packetData.getShort() & 0xFFFF;

    //skip checksum (2 bytes)
    packetData.getShort();

    IO.println(String.format("UDP data [ ports:  %d -> %d | length: %d bytes ]", srcPort, dstPort, length));

    if (srcPort == 53 || dstPort == 53) {
        parseDNSPacket(packetData);
    }

    if (srcPort == 443 || dstPort == 443) {
        parseMinimalQUICPacket(packetData);
    }
}

/**
 * Parses the ICMPv4 packet data from ipv4 packet data buffer
 * @param packetData
 * @param protocolFilters
 */
void parseICMPPacketV4(ByteBuffer packetData, List<String> protocolFilters) {
    if (!protocolFilters.contains("icmp") && !protocolFilters.isEmpty()) {
        return;
    }
    packetData.order(ByteOrder.BIG_ENDIAN);

    // extract the first bytes for type and code
    var type = packetData.get() & 0xFF;
    var code = packetData.get() & 0xFF;
    //get checksum on 2 next bytes
    var checksum = packetData.getShort() & 0xFFFF;

    //4 next bytes are header data
    var header = packetData.getInt();

    //type translation
    var typeDescription = switch (type) {
        case 0  -> "pong !";
        case 3  -> "destination unreachable";
        case 5  -> "redirect";
        case 8  -> "ping ! ";
        case 11 -> "time exceeded (TTL expired)";
        default -> "unknown type (" + type + ")";
    };

    //code translation
    var codeDescription = "";
    if (type == 3) {
        codeDescription = switch (code) {
            case 0 -> "net unreachable";
            case 1 -> "host unreachable";
            case 3 -> "port unreachable";
            default -> "code " + code;
        };
    }

    IO.println(String.format("ICMPv4 [ type: %s | code: %s | checksum: 0x%04X | header: 0x%08X ]", typeDescription, codeDescription, checksum, header));

    //now this is the payload data
    if (packetData.remaining() > 0) {
        parseDataPayload(packetData);
    }
}

/**
 * Parses the ICMPv6 packet data from ipv6 packet data buffer
 * It is not only used to do ping/pong, but also to discover neighbors like ARP protocol
 * @param packetData
 */
void parseICMPPacketV6(ByteBuffer packetData) {
    packetData.order(ByteOrder.BIG_ENDIAN);
    var type = packetData.get() & 0xFF;
    var code = packetData.get() & 0xFF;
    var checksum = packetData.getShort() & 0xFFFF;

    //4 next bytes are header data
    var restOfHeader = packetData.getInt();

    var typeDescription = switch (type) {
        case 1   -> "destination unreachable";
        case 2   -> "packet too big";
        case 3   -> "time exceeded (TTL expired)";
        case 4   -> "parameter problem";
        case 128 -> "ping !";
        case 129 -> "pong !";
        //ARP stuff like Neighbor Solicitation
        case 133 -> "router solicitation";
        case 134 -> "router advertisement";
        case 135 -> "neighbor solicitation";
        case 136 -> "neighbor advertisement";
        default  -> "unknown type (" + type + ")";
    };

    IO.println(String.format("ICMPv6 [ type: %s | code: %d | checksum: 0x%04X | header: 0x%08X ]", typeDescription, code, checksum, restOfHeader));

    //now this is the payload data
    if (packetData.remaining() > 0) {
        parseDataPayload(packetData);
    }
}

/**
 * Parse DNS packet data
 * @param packetData
 */
void parseDNSPacket(ByteBuffer packetData) {
    int dnsOffset = packetData.position();
    packetData.order(ByteOrder.BIG_ENDIAN);
    //header on next 12 bytes
    var id = packetData.getShort() & 0xFFFF;
    var flags = packetData.getShort() & 0xFFFF;
    var qd = packetData.getShort() & 0xFFFF;
    var an = packetData.getShort() & 0xFFFF;
    var ns = packetData.getShort() & 0xFFFF;
    var ar = packetData.getShort() & 0xFFFF;

    IO.println(String.format("DNS [ id: 0x%04X | q:%d a:%d auth:%d add:%d | flags:0x%04X ]", id, qd, an, ns, ar, flags));

    //queries
    for (int i = 0; i < qd; i++) {
        var dnsName = extractDNSName(packetData, dnsOffset);
        var qType = packetData.getShort() & 0xFFFF;
        var qClass = packetData.getShort() & 0xFFFF;
        IO.print(String.format("-> query target: %s (Type: %d) | qClass: %d", dnsName, qType, qClass));
    }

    //answers
    for (int i = 0; i < an; i++) {
        var dnsName = extractDNSName(packetData, dnsOffset);
        var aType = packetData.getShort() & 0xFFFF;
        var aClass = packetData.getShort() & 0xFFFF;
        var ttl = packetData.getInt() & 0xFFFFFFFFL;
        var rdLength = packetData.getShort() & 0xFFFF;

        if (aType == 1 && rdLength == 4) { //type A
            var ip = new byte[4];
            packetData.get(ip);
            IO.println(String.format("-> answer: %s -> A : [%s] | aClass: %d | ttl: %d | rdLength: %d", dnsName, formatIpAddress(ip), aClass, ttl, rdLength));
        } else if (aType == 28 && rdLength == 16) {// type AAAA
            var ip6 = new byte[16];
            packetData.get(ip6);
            IO.println(String.format("-> answer: %s -> AAAA : [%s] | aClass: %d | ttl: %d | rdLength: %d", dnsName, formatIpv6Address(ip6), aClass, ttl, rdLength));
        } else if (aType == 5) {// CNAME
            var cname = extractDNSName(packetData, dnsOffset);
            IO.println(String.format("-> answer: %s -> CNAME : [%s] | aClass: %d | ttl: %d | rdLength: %d", dnsName, cname, aClass, ttl, rdLength));
        } else {
            //other types, skip the data
            packetData.position(packetData.position() + rdLength);
            IO.println(String.format("-> answer: %s -> ? : [skip %d bytes]", dnsName, rdLength));
        }
    }
}

/**
 * Try to parse a packet under QUIC protocol for HTTP/3
 * This is the best effort parser, it may not handle all cases correctly.
 * @param packetData
 */
void parseMinimalQUICPacket(ByteBuffer packetData) {
    if (packetData.remaining() < 1) return;

    packetData.order(ByteOrder.BIG_ENDIAN);
    int firstByte = packetData.get() & 0xFF;

    //bit 7 (0x80) check if the packet has a long header
    boolean isLongHeader = (firstByte & 0x80) != 0;

    if (isLongHeader) {
        if (packetData.remaining() < 4)
            return;

        //version on 4 bytes
        var version = packetData.getInt();
        //dest connection id (DCID)
        var dcidLen = packetData.get() & 0xFF;
        var dcid = new byte[dcidLen];

        if (packetData.remaining() >= dcidLen)
            packetData.get(dcid);

        //src connection id (SCID)
        var scidLen = packetData.get() & 0xFF;
        var scid = new byte[scidLen];

        if (packetData.remaining() >= scidLen)
            packetData.get(scid);

        IO.println(String.format("QUIC (minimal) [ type: long header (0x%02X) | version: 0x%08X | DCID: %s (len: %d) | SCID: %s (len: %d) ]", firstByte, version, bytesToHex(dcid), dcidLen, bytesToHex(scid), scidLen));

    } else {
        //this is a short header
        IO.println(String.format("QUIC (minimal) [ type: short header (0x%02X) ]", firstByte));
    }
}
/**
 * Reads a DNS name from the packet data buffer
 * Handle the compression by jumping to the correct offset
 * @param buffer
 * @param dnsOffset
 * @return
 */
String extractDNSName(ByteBuffer buffer, int dnsOffset) {
    var sb = new StringBuilder();
    var jumped = false;
    var savedPos = -1;

    while (true) {
        var len = buffer.get() & 0xFF; // get length of the name
        if (len == 0) break; // end of name

        if ((len & 0xC0) == 0xC0) { //this is a pointer to another name
            var offset = ((len & 0x3F) << 8) | (buffer.get() & 0xFF);
            if (!jumped) {
                savedPos = buffer.position(); // save for returning after the jump
                jumped = true;
            }
            buffer.position(dnsOffset + offset);
        } else {
            var label = new byte[len];
            buffer.get(label);
            sb.append(new String(label)).append(".");
        }
    }

    if (jumped) buffer.position(savedPos); //go back to the saved position
    return sb.toString();
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

void readPackets(PcapFileFormat pcapFileFormat, ByteBuffer packetDataBuffer, List<String> protocolFilters) {
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
        readPacket(packetCount, timestampSeconds, timestampMicroSeconds, capturedLength, packetLength, packetData, protocolFilters);
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

/**
 * Parses the data payload from the packet data buffer
 * Print data payload as hex string and try to decode it as ascii text
 * @param packetData
 */
void parseDataPayload(ByteBuffer packetData) {
    var remaining = packetData.remaining();
    if (remaining <= 0) {
        IO.println("No remaining data to parse as payload");
        return;
    }
    byte[] payload = new byte[remaining];
    packetData.get(payload);
    IO.println("raw payload data: " + bytesToHex(payload));
    var asciiBuilder = new StringBuilder();
    for (byte b : payload) {
        var value = b & 0xFF;
        if (value >= 32 && value <= 126) {
            //printable ascii character between 32 and 126 char code
            asciiBuilder.append((char) value);
        } else {
            //non-printable character, print as dot
            asciiBuilder.append('.');
        }
    }
    IO.println("ascii payload: " + asciiBuilder);
}

/**
 * Converts a byte array to a hexadecimal string
 * @param bytes
 * @return the hexadecimal string
 */
String bytesToHex(byte[] bytes) {
    StringBuilder sb = new StringBuilder();
    for (byte b : bytes) {
        sb.append(String.format("%02X ", b & 0xFF));
    }
    return sb.toString();
}