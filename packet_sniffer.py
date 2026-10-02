from scapy.all import IP, ICMP, sniff, TCP, UDP


packet_counts = {
    "ICMP": 0,
    "TCP": 0,
    "UDP": 0
}

unique_source_IPs = set()
unique_destination_IPs = set()

def explain_flags(flag):
    match flag:
        case "S":
            # Starts a 3 way handshake
            return "Synchronize"

        case "A":
            # Confirms a packet or data was succesefully sent
            return "Acknowledgment"

        case "SA":
            # Synchronize and Acknowledges
            return "Synchronize and Acknowledgment"

        case "PA":
            # Push and Acknowledgment
            # Tells the reciver to process data
            return "Push and Acknowledgment"

        case "FA":
            # Finish and Acknowledgment
            # Signals that one side is clsoing the connection
            return "Finish and Acknowledgment"

        case "F":
            # Connection is closing
            return "Finish"

        case "R":
            # Abort a connection due to error
            return "Reset"

        case "P":
            # Push data to the application layer
            return "Push"

        case "U":
            # Urgent pointer field is valid
            return "Urgent"

        case "E":
            # Signals that the host is Explicit Congestion Notification
            # capable or has received a congestion notification
            return "ECN-Echo"

        case "C":
            # Acknowledges the echo
            return "Congestion Window Reduced"

        case "N":
            # Protection against hidden or malicious concealment
            # of congestion signals
            return "Nonce Sum"
            
        case "RA":
            # Reset and Acknowledgment
            return "Reset and Acknowledgment"

        case "RPA":
            # Reset, Push, and Acknowledgment
            return "Reset, Push, and Acknowledgment"

        case "FA":
            # Finish and Acknowledgment
            return "Finish and Acknowledgment"

        case "FPA":
            # Finish, Push, and Acknowledgment
            return "Finish, Push, and Acknowledgment"

        case "FS":
            # Finish and Synchronize
            return "Finish and Synchronize"

        case "FSA":
            # Finish, Synchronize, and Acknowledgment
            return "Finish, Synchronize, and Acknowledgment"

        case _:
            # Handles TCP flag combinations that are not
            # explicitly listed above
            return f"Unknown/Combined Flags: {flag}"


def packet_callback(packet):

    # Check for IP and (ICMP (Ping) or TCP or UDP)
    # ICMP is networking Layer 3
    # TCP is reliable data Layer 4. Eg text, email
    # UDP is fast Layer 4. Eg video, streaming
    if packet.haslayer(IP) and (
        packet.haslayer(ICMP)
        or packet.haslayer(TCP)
        or packet.haslayer(UDP)
    ):

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        global unique_source_IPs
        global unique_destination_IPs
        
        if src_ip not in unique_source_IPs:
        	unique_source_IPs.add(src_ip)
        	
        if dst_ip not in unique_destination_IPs:
        	unique_destination_IPs.add(dst_ip)

        if packet.haslayer(ICMP):

            log_line = (f"ICMP Packet: {src_ip} -> {dst_ip}\n")
            print(log_line.strip())
            packet_counts["ICMP"] += 1

        elif packet.haslayer(TCP):

            log_line = (
                f"TCP Packet: {src_ip}:{packet[TCP].sport} -> "
                f"{dst_ip}:{packet[TCP].dport} | "
                f"Flags: {explain_flags(packet[TCP].flags)}\n"
            )

            print(log_line.strip())

            packet_counts["TCP"] += 1

        elif packet.haslayer(UDP):

            log_line = (
                f"UDP Packet: {src_ip}:{packet[UDP].sport} -> "
                f"{dst_ip}:{packet[UDP].dport}\n"
            )

            print(log_line.strip())

            packet_counts["UDP"] += 1

        # Writes the networked traffic to a file called network_log.txt
        with open("network_log.txt", "a") as f:
            f.write(log_line)


print("Starting packet capture... Press Ctrl+C to stop.")

packet_count = int(
    input("Please enter the number of packets you want to track: ")
)


# Change the BPF filter to listen for ICMP, TCP, or UDP
# "ip" makes the BPF filter match the IPv4 check
# inside packet_callback()
sniff(
    filter="ip and (icmp or tcp or udp)",
    prn=packet_callback,
    count=packet_count
)


# Prints the capture summary
print("=" * 20, "Capture Summary", "=" * 20)
print()

total_packets = (
    packet_counts["ICMP"]
    + packet_counts["TCP"]
    + packet_counts["UDP"]
)

print("Total packets:", total_packets)

print()
print("ICMP:", packet_counts["ICMP"])
print("TCP:", packet_counts["TCP"])
print("UDP:", packet_counts["UDP"])

print()
print("Unique source IP's: ", len(unique_source_IPs))
print("Unique destination IP's: ", len(unique_destination_IPs))

print()
print("=" * 58)
