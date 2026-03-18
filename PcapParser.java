import java.io.*;
import java.util.*;
import java.nio.*;

enum PcapFileFormat {
    BIG_ENDIAN_MICRO_SECONDS,
    LITTLE_ENDIAN_MICRO_SECONDS,
    BIG_ENDIAN_NANO_SECONDS,
    LITTLE_ENDIAN_NANO_SECONDS
}

void main(String[] args) {

    if (args.length != 1) {
        IO.println("Usage: java PcapParser <.pcap file>");
        System.exit(1);
    }

    String pcapFile = args[0];

    if (!pcapFile.endsWith(".pcap")) {
        IO.println("Error: PCAP file must have a .pcap extension");
        System.exit(1);
    }

    try (FileInputStream pcapStream = new FileInputStream(pcapFile)) {
        byte[] bytes = pcapStream.readAllBytes();
        //extract pcap header on 24 bytes
        byte[] pcapHeader = Arrays.copyOfRange(bytes, 0, 24);
        //the magic number is on the first 4 bytes of the header
        ByteBuffer magicNumberBuffer = ByteBuffer.wrap(pcapHeader, 0, 4);
        PcapFileFormat pcapFileFormat = getPcapFileFormat(magicNumberBuffer);
        if (pcapFileFormat == null) {
            IO.println("Error: PCAP file is not in a supported format");
            System.exit(1);
        }
        IO.println("Pcap file format: " + pcapFileFormat);
        //the versions are on the next 4 bytes after the magic number
        ByteBuffer versionsBuffer = ByteBuffer.wrap(pcapHeader, 4, 8);
        int[] pcapVersions = getPcapVersions(pcapFileFormat, versionsBuffer);
        IO.println("Pcap versions: " + Arrays.stream(pcapVersions).mapToObj(Integer::toString).collect(Collectors.joining(".")));
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
 * @return [majorVersion, minorVersion] as an int array of length 2
 */
int[] getPcapVersions(PcapFileFormat pcapFileFormat, ByteBuffer versionsBuffer) {
    if (versionsBuffer.remaining() < 4) {
        throw new RuntimeException("Versions buffer must contain at least 4 bytes");
    }
    switch (pcapFileFormat) {
        case BIG_ENDIAN_MICRO_SECONDS, BIG_ENDIAN_NANO_SECONDS:
            versionsBuffer.order(ByteOrder.BIG_ENDIAN);
            break;
        case LITTLE_ENDIAN_MICRO_SECONDS, LITTLE_ENDIAN_NANO_SECONDS:
            versionsBuffer.order(ByteOrder.LITTLE_ENDIAN);
            break;
    }
    int majorVersion = versionsBuffer.getShort(); //a short is 2 bytes
    int minorVersion = versionsBuffer.getShort(); //a short is 2 bytes
    return new int[] { majorVersion, minorVersion };
}