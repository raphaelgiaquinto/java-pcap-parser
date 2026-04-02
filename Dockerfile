FROM openjdk:25-ea-jdk

WORKDIR /app

COPY PcapParser.java .

RUN javac --enable-preview --release 25 PcapParser.java

ENTRYPOINT ["java", "PcapParser"]