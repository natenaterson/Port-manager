from scapy.all import IP, ICMP, sniff  # Change TCP to ICMP here

def packet_callback(packet):
    # Check for IP and ICMP (Ping)
    if packet.haslayer(IP) and packet.haslayer(ICMP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        log_line = f"ICMP Packet: {src_ip} -> {dst_ip}\n"
        print(log_line.strip())
        
        #Writes the networked traffic to a file called network_log.txt
        with open("network_log.txt", "a") as f:
            f.write(log_line)

print("Starting packet capture... Press Ctrl+C to stop.")
# Change the BPF filter to listen for icmp
sniff(filter="icmp", prn=packet_callback, count=10)
