# Port-manager


## Hello 

These are files for reading ports and packets.
These Are meant to be run in Kali.

### Port Scanner
Used to scan ports.

### Packet Sniffer
This is a packet sniffer that relies on scapy.
Run the packet sniffer with:
sudo python3 .../Port-manager/packet_sniffer.py

The Packet sniffer dispalys the info in the form of:

(Date and time) | (Packet Type) Packet: source.port -> destination.port | bytes: (bytes) | Flags: Flag description
Flags are only displyed for TCP packets.
Port is displayed for TCP, and UDP.

At the end it will display the summary of the Packet information.
The date and time the packet was captured.
The Byte size of the packet.
The number of packets.
The nubmer of TCP, UDP, and ICMP.
The number of unique source and destination IPs.

Here are several commands that can be run in Kali to test the packet sniffer:

|Protocol		|Command				|Expected Result|
| :--- | :---: | ---: |
|TCP		|curl -I https://example.com	|TCP packets, usually port 443|
|UDP		|nslookup example.com		|DNS traffic, commonly UDP port 53|
|ICMP		|ping -c 4 8.8.8.8		|ICMP Echo Requests and Replies|
|ICMP		|ping -c 100 google.com		|ICMP Echo Requests and Replies|


### Arp Monitor
The test classes for the arp monitor were written by claude.
To test the arp montior run python3 -m unittest -v test_arp_monitor
An Arp montior is something that checks packes to see if a decivice is using multiple IPs.
Checks if a packet's IP has be in the netwrok previouslly and used a different mac address before.
