"""
packet_sniffer.py
This file is a packet sniffer for reading packet info on a screen.
This is written by Nate Montgomery
Created on October 2, 2026.
"""

import logging
import os
import sys
from datetime import datetime

from scapy.all import ICMP, IP, TCP, UDP, sniff

log_file = "network_log.txt"

BPF_filter = "ip and (icmp or tcp or udp)"

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
}

unique_source_ips = set()
unique_destination_ips = set()
total_bytes = 0

logger = logging.getLogger("packet_sniffer")

#This method was written by Calude
def setup_logging():
    """Open the log file once. Every packet is then written through it."""
    handler = logging.FileHandler(log_file, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

#This method was written by Calude
def explain_flags(flags):
    """Turn Scapy TCP flags such as 'SA' into readable names."""
    letters = str(flags)
    if not letters:
        return "No Flag"
    names = [TCP_flag_names.get(letter, f"Unknown({letter})") for letter in letters]
    return " + ".join(names)

"""
Handles the packet collecting information.
This is the most important method in the file.
"""
def packet_callback(packet):
    global total_bytes

    # Only handle IPv4 packets that carry ICMP (ping), TCP or UDP.
    # ICMP is networking layer 3.
    # TCP is reliable layer 4 data. Eg text, email.
    # UDP is fast layer 4 data. Eg video, streaming.
    if not packet.haslayer(IP):
        return

    if packet.haslayer(ICMP):
        protocol = "ICMP"
        src = packet[IP].src
        dst = packet[IP].dst
        extra = ""
    elif packet.haslayer(TCP):
        protocol = "TCP"
        src = f"{packet[IP].src}:{packet[TCP].sport}"
        dst = f"{packet[IP].dst}:{packet[TCP].dport}"
        extra = f" | Flags: {explain_flags(packet[TCP].flags)}"
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src = f"{packet[IP].src}:{packet[UDP].sport}"
        dst = f"{packet[IP].dst}:{packet[UDP].dport}"
        extra = ""
    else:
        return

    unique_source_ips.add(packet[IP].src)
    unique_destination_ips.add(packet[IP].dst)

    packet_bytes = len(packet)
    total_bytes += packet_bytes
    packet_counts[protocol] += 1

    timestamp = datetime.fromtimestamp(float(packet.time))

    log_line = (
        f"{timestamp} | {protocol:<4} | {src} -> {dst} | "
        f"Bytes: {packet_bytes}\t{extra}"
    )

    print(log_line)
    logger.info(log_line)

"""
Prints the Summary at the of the packet collection.
"""
def print_summary():
    print("=" * 20, "Capture Summary", "=" * 20)
    print()

    print("Total packets:", sum(packet_counts.values()))

    print()
    print("ICMP:", packet_counts["ICMP"])
    print("TCP:", packet_counts["TCP"])
    print("UDP:", packet_counts["UDP"])

    print()
    print("Unique source IPs:", len(unique_source_ips))
    print("Unique destination IPs:", len(unique_destination_ips))

    print()
    print("Total bytes:", total_bytes)

    print()
    print("=" * 58)

"""
Gets the input of the file to know how many pakcets need to be checked.
"""
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

"""
This is the main function that starts the program.
"""
def main():
    # Sniffing needs raw socket access. Needs admin acess.
    if os.geteuid() != 0:
        sys.exit("This program must be run as root. Try: sudo python3 packet_sniffer.py")

    packet_count = get_packet_count()
    setup_logging()

    print("Starting packet capture... Press Ctrl+C to stop "
          "or wait for the number of packets to be sniffed.")

    try:
        # store=False keeps Scapy from holding every packet in memory.
        sniff(
            filter=BPF_filter,
            prn=packet_callback,
            count=packet_count,
            store=False,
        )
    except KeyboardInterrupt:
        print()
    finally:
        # Runs whether the count finished or Ctrl+C was pressed,
        # so the summary prints exactly once.
        print_summary()


#This was written by calude
if __name__ == "__main__":
    main()
