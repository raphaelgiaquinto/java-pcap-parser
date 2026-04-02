## Java PCAP file parser

### Description

**( This is a work in progress project )**

Java Pcap Parser used to parse pcap files generated from applications like **Wireshark**.

It uses pure Java 25 API, no external libraries.

Implementation is based on the following documentation: https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcap/

**It is not intended to be used for .pcapng files**

### Requirements
- Java 25+ (if you want to run the parser without docker)
- Docker (if you want to run the parser in a Docker container)
- A .pcap file to parse

### Build without docker

```bash
javac PcapParser.java
```

### Build with docker

```bash
docker build -t pcap-parser .
```

### Run without docker

To run the parser, execute the following command:

```bash
java PcapParser <pcap_file_path> --proto<tcp|udp|dns|arp|icmp> (optional)
```

### Run with docker

To run the parser in a Docker container, execute the following command:

```bash
docker docker run --rm -v "$PWD:/data" pcap-parser /data/<your_pcap_file>.pcap --proto<tcp|udp|dns|arp|icmp> (optional)
```

### Protocols supported
- TCP
- UDP
- DNS
- ARP
- ICMP
- QUIC with minimal parse (enabled if you run with the udp flag)

### Screenshots
An exemple of the output of the parser:
![Screenshot](/img/pcap.png)
