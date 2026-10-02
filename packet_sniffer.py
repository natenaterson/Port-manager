from scapy.all import IP, ICMP, sniff, TCP, UDP

def packet_callback(packet):
    # Check for IP and (ICMP (Ping) or TCP or UDP) 
    #ICMP is networking Layer 3
    #TCP is reliabble data Layer 4. Eg text, email
    #UDP is fast Layer 4. Eg video, streaming
    if packet.haslayer(IP) and (packet.haslayer(ICMP) or packet.haslayer(TCP) or packet.haslayer(UDP)):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        log_line = f"Packet: {src_ip} -> {dst_ip}\n"
        print(log_line.strip())
        
        #if packet.haslayer(ICMP):
        #	print(log_line.strip())
        #elif packet.haslayer(TCP):
        #	print(packet[TCP].sport)
        #	print(packet[TCP].dport)
        #elif packet.haslayer(UDP):
        #	print(packet[UDP].sport)
        #	print(packet[UDP].dport)
        
        
        #Writes the networked traffic to a file called network_log.txt
        with open("network_log.txt", "a") as f:
            f.write(log_line)

print("Starting packet capture... Press Ctrl+C to stop.")
# Change the BPF filter to listen for icmp
sniff(filter="icmp or tcp or udp", prn=packet_callback, count=10)
