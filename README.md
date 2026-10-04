# Port-manager


Small Python tools for looking at ports and network packets.
These Are meant to be run in Kali Linux and use [Scapy](https://scapy.net/).

##Contents
|File	|What it does|
| :--- |  ---: |
|packet_sniffer.py	|Shows ARP, ICMP, TCP and UDP packets as they are captured|
|arp_monitor.py	Checks |ARP packets for signs of ARP spoofing (used by the sniffer)|
|arp_test_traffic.py	|Makes fake ARP packets for testing (written by Claude)|
|test_arp_monitor.py	|Unit tests for arp_monitor.py (written by Claude)|

### Port Scanner
Used to scan ports.

### Packet Sniffer
This is a packet sniffer that relies on scapy.
Run the packet sniffer with:
sudo python3 .../Port-manager/packet_sniffer.py
You neeed to be in the file directory to run it.

The program will then ask how many packets you want to capture(0 is until ctrl+C)

| Option | Meaning |
| :--- | :--- |
| `-c`, `--count N` | Number of packets to capture. `0` means until Ctrl+C. |
| `-i`, `--iface IFACE` | Interface to capture on, for example `eth0`. |
| `-r`, `--pcap FILE` | Read packets from a `.pcap` file instead of the network. No root needed. |

Example: `sudo python3 packet_sniffer.py -i eth0 -c 50`

### What it shows

Each packet is printed on one line and also written to `network_log.txt`:

```
(Date and time captured) | (Type) | (details) | Bytes: (size) | Flags: (flags)
```

| Type | Details shown |
| :--- | :--- |
| TCP | `source IP:port -> destination IP:port`, plus the TCP flags |
| UDP | `source IP:port -> destination IP:port` |
| ICMP | `source IP -> destination IP` |
| ARP | A request (`who-has 192.168.1.1? tell 192.168.1.20 (mac)`) or a reply (`192.168.1.1 is-at (mac)`) |

- **Bytes** is the size of the whole captured frame, not just the IP part.
- **Flags** are only shown for TCP packets.
- Ports are only shown for TCP and UDP.
- Suspicious ARP packets also print an `ALERT` line.

### Summary

When the capture ends it prints:

- The total number of packets
- The number of ARP, ICMP, TCP and UDP packets
- The number of ARP alerts
- The number of unique source and destination IPs (ARP addresses are not counted)
- The total number of bytes

### Limits

- Only **IPv4** is supported. IPv6 packets are ignored.
- It only sees traffic that reaches this machine. Other devices' Wi-Fi traffic needs monitor mode, which most setups do not have.
- On **WSL2** the Kali install sits behind a virtual network, so it only sees its own traffic and the virtual gateway.
- `network_log.txt` is created in the folder you run the program from, and new packets are added to the end of it each run.

### Trying it out

Run these in a second terminal while the sniffer is running. The `-4` makes sure IPv4 is used, since IPv6 is not shown.

| Protocol | Command | Expected result |
| :--- | :--- | :--- |
| TCP | `curl -4 -I https://example.com` | TCP packets, usually port 443 |
| UDP | `nslookup example.com` | DNS traffic, commonly UDP port 53 |
| ICMP | `ping -4 -c 4 8.8.8.8` | ICMP echo requests and replies |
| ARP | `sudo ip neigh flush all` then `ping -4 -c 1 <gateway IP>` | An ARP request and reply |

Find your gateway IP with `ip route | grep default`. Type the address on its own, without `< >`.


## ARP Monitor

ARP matches an IP address to a MAC address, and it has no way to check that the answer is true. In ARP spoofing an attacker claims to own another device's IP (often the gateway) so traffic is sent to them.

`arp_monitor.py` trusts the first MAC it sees for each IP, then reports two things:

1. **An IP changes MAC address.** An IP that was first seen with one MAC is now claimed by a different one.
2. **The headers disagree.** The Ethernet source MAC of an ARP packet differs from the MAC inside the ARP message.

Each problem is reported once, so a spoofing tool that repeats itself does not flood the screen. ARP probes from `0.0.0.0` are ignored because they are normal.

Things to know:

- If a spoofer is already active when the program starts, its first claim is trusted by mistake.
- Normal changes can cause false alerts, such as DHCP giving an address to a new device, virtual machines, router failover, and phones that randomize their MAC.
- ARP is IPv4 only. The IPv6 version of this attack is not checked.
- On Wi-Fi without monitor mode, ARP requests are visible to everyone, but replies are only seen by the device they are sent to.

### Unit tests

The tests need `arp_test_traffic.py` and `test_arp_monitor.py` in the same folder as `arp_monitor.py`:

```bash
python3 -m unittest -v test_arp_monitor
```

### Testing with the packet sniffer

This makes a pcap of fake packets and reads it. Nothing is sent on the network.

```bash
python3 arp_test_traffic.py --pcap arp_test.pcap
python3 packet_sniffer.py --pcap arp_test.pcap --count 0
```

Expected result: 8 packets (7 ARP and 1 ICMP), and 2 `ALERT` lines. One is for the spoofed gateway and one is for the Ethernet mismatch. The repeated spoof is not reported a second time.

### Live test

To test on a real interface without touching your network, use a virtual pair:

```bash
sudo ip link add veth0 type veth peer name veth1
sudo ip link set veth0 up
sudo ip link set veth1 up
```

In one terminal: `sudo python3 packet_sniffer.py -i veth1 -c 0`

In another: `sudo python3 arp_test_traffic.py --iface veth0`

When finished: `sudo ip link del veth0`

`arp_test_traffic.py` refuses to send on any interface that does not start with `veth` or `dummy`, because its packets pretend to be a gateway and would disrupt a real network.

## Files not to commit

Add these to `.gitignore` (the file must be named exactly `.gitignore`, with no `.txt`):

```
network_log.txt
*.pcap
__pycache__/
```

`network_log.txt` and real captures contain the addresses of your network and the sites you visit.
