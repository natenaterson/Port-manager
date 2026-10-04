"""
packet_sniffer.py
This file is a packet sniffer for reading packet info on a screen.
This is written by Nate Montgomery.
Created on October 2, 2026.
Some functions were written with help from Calude.
 
Shows IPv4 ICMP, TCP and UDP packets plus ARP packets, and uses
arp_monitor.py to raise alerts for possible ARP spoofing.
"""

import argparse
import logging
import os
import sys
from datetime import datetime
 
from scapy.all import ARP, ICMP, IP, TCP, UDP, sniff
 
import arp_monitor

log_file = "network_log.txt"

BPF_filter = "arp or (ip and (icmp or tcp or udp))"

# One entry per single TCP flag. Combinations are built from these
# so every possible combination is handled automatically.
TCP_flag_names = {
    "F": "Finish",                      # Connection is closing
    "S": "Synchronize",                 # Starts the 3 way handshake
    "R": "Reset",                       # Abort a connection due to error
    "P": "Push",                        # Push data to the application layer
    "A": "Acknowledgment",              # Confirms data was successfully sent
    "U": "Urgent",                      # Urgent pointer field is valid
    "E": "ECN-Echo",                    # Signals that the host is Explicit Congestion Notification capable or has received a congestion notification
    "C": "Congestion Window Reduced",   # Acknowledges the ECN echo
    "N": "Nonce Sum",                   # Protects against hidden or malicious concealment of congestion signals
}

packet_counts = {
    "ICMP": 0,
    "TCP": 0,
    "UDP": 0,
    "ARP": 0,
}

arp_alert_count = 0

# Only IP packets are added to these. ARP addresses are not counted here.
unique_source_ips = set()
unique_destination_ips = set()
total_bytes = 0	#The total byte size includes the IP, and ARP packets.

logger = logging.getLogger("packet_sniffer")

#This method was written by Calude
def setup_logging():
    """Open the log file once. Every packet is then written through it."""
    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    logger.propagate = False

#This method was written by Calude
def explain_flags(flags):
    """Turn Scapy TCP flags such as 'SA' into readable names."""
    letters = str(flags)
    if not letters:
        return "No Flag"
    names = [TCP_flag_names.get(letter, f"Unknown({letter})") for letter in letters]
    return " + ".join(names)

#This method was written by Calude
def capture_time(packet):
    """When the packet was captured, not when this program handled it."""
    return datetime.fromtimestamp(float(packet.time))
 
#This method was written by Calude
def show(timestamp, protocol, detail, size, extra=""):
    """Build one log line, then print it and write it to the log file."""
    line = f"{timestamp} | {protocol:<4} | {detail} | Bytes: {size}{extra}"
    print(line)
    logger.info(line)
 
#This method was written by Calude
def describe_arp(arp):
    """A short readable description of an ARP packet."""
    if arp.op == 1:
        return f"who-has {arp.pdst}? tell {arp.psrc} ({arp.hwsrc})"
    if arp.op == 2:
        return f"{arp.psrc} is-at {arp.hwsrc}"
    return f"op {arp.op} {arp.psrc} ({arp.hwsrc}) -> {arp.pdst}"
    
def handle_arp(packet):
    """Log an ARP packet and print any alerts from arp_monitor."""
    global total_bytes, arp_alert_count
    
    size = len(packet)
    total_bytes += size
    packet_counts["ARP"] += 1
    timestamp = capture_time(packet)
    
    show(timestamp, "ARP", describe_arp(packet[ARP]), size)

    for alert in arp_monitor.check_arp(packet):
        arp_alert_count += 1
        alert_line = f"{timestamp} | ALERT | {alert}"
        print(alert_line)
        logger.warning(alert_line)


def packet_callback(packet):
    """
    Called by sniff() for every packet that passes the filter.
    Handles the acutal packet infomation collection.
    ARP goes to handle_arp(). Everything else must be IPv4 carrying
    ICMP, TCP or UDP.
    """
    global total_bytes
    
    #Calls handle_arp for all ARP packets
    if packet.haslayer(ARP):
        handle_arp(packet)
        return

    # Only handle IPv4 packets that carry ICMP (ping), TCP or UDP.
    # ICMP is networking layer 3.
    # TCP is reliable layer 4 data. Eg text, email.
    # UDP is fast layer 4 data. Eg video, streaming.
    if not packet.haslayer(IP):
        return

    if packet.haslayer(ICMP):
        protocol = "ICMP"
        detail = f"{packet[IP].src} -> {packet[IP].dst}"
        extra = ""
    elif packet.haslayer(TCP):
        protocol = "TCP"
        detail = (
            f"{packet[IP].src}:{packet[TCP].sport} -> "
            f"{packet[IP].dst}:{packet[TCP].dport}"
        )
        extra = f" | Flags: {explain_flags(packet[TCP].flags)}"
    elif packet.haslayer(UDP):
        protocol = "UDP"
        detail = (
            f"{packet[IP].src}:{packet[UDP].sport} -> "
            f"{packet[IP].dst}:{packet[UDP].dport}"
        )
        extra = ""
    else:
        return

    unique_source_ips.add(packet[IP].src)
    unique_destination_ips.add(packet[IP].dst)

    size = len(packet)
    total_bytes += size
    packet_counts[protocol] += 1

    show(capture_time(packet), protocol, detail, size, extra)

def print_summary():
    """Print the capture summary."""
    print("\n")
    print("=" * 20, "Capture Summary", "=" * 20)
    
    print()
    print("Total packets:", sum(packet_counts.values()))

    print()
    print("ICMP:", packet_counts["ICMP"])
    print("TCP:", packet_counts["TCP"])
    print("UDP:", packet_counts["UDP"])
    print("ARP:", packet_counts["ARP"])
    
    print()
    print("ARP alerts:", arp_alert_count)

    print()
    print("Unique source IPs:", len(unique_source_ips))
    print("Unique destination IPs:", len(unique_destination_ips))

    print()
    print("Total bytes:", total_bytes)

    print()
    print("=" * 58)


def get_packet_count():
    """Ask how many packets to capture. 0 means capture until Ctrl+C."""
    while True:
        try:
            count = int(input(
                "Please enter the number of packets you want to track "
                "(0 is until ctrl+C): "
            ))
        except ValueError:
            print("Invalid input! Please enter a valid whole number.")
            continue
        except (KeyboardInterrupt, EOFError):
            print("\nCancelled.")
            sys.exit(0)
        if count < 0:
            print("Please enter 0 or a positive number.")
            continue
        return count

#This was written by Calude
def parse_args():
    """Optional command line settings. With none, it asks for a count."""
    parser = argparse.ArgumentParser(
        description="Show ARP, ICMP, TCP and UDP packets and watch for ARP spoofing."
    )
    parser.add_argument(
        "-c", "--count", type=int,
        help="number of packets to capture (0 = until Ctrl+C)",
    )
    parser.add_argument(
        "-i", "--iface",
        help="interface to capture on, for example eth0 (default: Scapy's default)",
    )
    parser.add_argument(
        "-r", "--pcap", metavar="FILE",
        help="read packets from a .pcap file instead of the network",
    )
    args = parser.parse_args()
    if args.count is not None and args.count < 0:
        parser.error("--count must be 0 or a positive number")
    return args

def main():
    args = parse_args()
 
    # Reading a file needs no special rights. Live sniffing needs root.
    if args.pcap:
        if not os.path.isfile(args.pcap):
            sys.exit(f"Cannot find the pcap file: {args.pcap}")
    elif os.geteuid() != 0:
        sys.exit("This program must be run as root. "
                 "Try: sudo python3 packet_sniffer.py")
 
    packet_count = args.count if args.count is not None else get_packet_count()
    setup_logging()
 
    sniff_options = {
        "filter": BPF_filter,
        "prn": packet_callback,
        "count": packet_count,
        "store": False,  # keeps Scapy from holding every packet in memory
    }
    if args.pcap:
        sniff_options["offline"] = args.pcap
        print(f"Reading packets from {args.pcap}...")
    else:
        if args.iface:
            sniff_options["iface"] = args.iface
        print("Starting packet capture... Press Ctrl+C to stop "
              "or wait for the number of packets to be sniffed.")
 
    try:
        sniff(**sniff_options)
    except KeyboardInterrupt:
        print()
    finally:
        # Runs whether the count finished or Ctrl+C was pressed,
        # so the summary prints exactly once.
        print_summary()


#This was written by Calude
if __name__ == "__main__":
    main()
