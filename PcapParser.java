/**
 * PcapParser written in java
 * Based on the documentation found: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/
 *
 * @author raphaelgiaquinto
 */

import java.io.*;
import java.util.*;
import java.nio.*;

enum PcapFileFormat {
    BIG_ENDIAN_MICRO_SECONDS,
    LITTLE_ENDIAN_MICRO_SECONDS,
    BIG_ENDIAN_NANO_SECONDS,
    LITTLE_ENDIAN_NANO_SECONDS
}

record PcapVersion(int majorVersion, int minorVersion) {}

record LinkTypeAndAdditionalInfo(int fcsLen, int r, int p, int reserved3, int linkType) {}

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
        //all of the next bytes are the packet data
        var packetDataBuffer = bytes.slice( 24, bytes.remaining() - 24);
        IO.println("Packet data:" + packetDataBuffer.remaining());
    } catch (IOException e) {
        IO.println("Error reading PCAP file: " + e.getMessage());
        System.exit(1);
    }
}

/**
 * Extracts the pcap file format from the magic number
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
 * Extracts the major and minor versions from the pcap header
 * @param pcapFileFormat the pcap file format extracted from the magic number
 * @param versionsBuffer byte buffer containing the versions on 4 bytes
 * @return the major and minor versions as record
 */

PcapVersion getPcapVersions(PcapFileFormat pcapFileFormat, ByteBuffer versionsBuffer) {
    if (versionsBuffer.remaining() != 4) {
        throw new RuntimeException("Versions buffer must contain 4 bytes");
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
 * @param pcapFileFormat
 * @param snapLenBuffer
 * @return the snap length
 */
int getSnapLen(PcapFileFormat pcapFileFormat, ByteBuffer snapLenBuffer) {
    if (snapLenBuffer.remaining() != 4) {
        throw new RuntimeException("Snap len buffer must contain 4 bytes");
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
 * @param pcapFileFormat
 * @param linkTypeAdditionalInfoBuffer
 * @return the linktype and additional information as record
 */
LinkTypeAndAdditionalInfo getLinkTypeAndAdditionalInformation(PcapFileFormat pcapFileFormat, ByteBuffer linkTypeAdditionalInfoBuffer) {
    if (linkTypeAdditionalInfoBuffer.remaining() != 4) {
        throw new RuntimeException("Link type buffer must contain 4 bytes");
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