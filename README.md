# Port-manager


Hello these are files for reading ports and packets.
These Are meant to be run in Kali.

Here are several commands that can be run in Kali to test the packet sniffer:
Protocol		Command				Expected Result
TCP		curl -I https://example.com	TCP packets, usually port 443
UDP		nslookup example.com		DNS traffic, commonly UDP port 53
ICMP		ping -c 4 8.8.8.8		ICMP Echo Requests and Replies
ICMP		ping -c 100 google.com		ICMP Echo Requests and Replies
