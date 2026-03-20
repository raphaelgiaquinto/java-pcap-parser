## Java PCAP file parser

### Description

**( This is a work in progress project )**

Java Pcap Parser used to parse pcap files generated from applications like **Wireshark**.

It uses pure Java 25 API, no external libraries.

Implementation is based on the following documentation: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/

**It is not intended to be used for .pcapng files**

### Requirements
- Java 25+
- A .pcap file to parse

### Build

```bash
javac PcapParser.java
```

### Usage

To run the parser, execute the following command:

```bash
java PcapParser <pcap_file_path>
```
