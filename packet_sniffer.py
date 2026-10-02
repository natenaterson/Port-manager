from scapy.all import IP, ICMP, sniff, TCP, UDP

def packet_callback(packet):
    # Check for IP and (ICMP (Ping) or TCP or UDP) 
    #ICMP is networking Layer 3
    #TCP is reliabble data Layer 4. Eg text, email
    #UDP is fast Layer 4. Eg video, streaming
    if packet.haslayer(IP) and (packet.haslayer(ICMP) or packet.haslayer(TCP) or packet.haslayer(UDP)):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        
        
        if packet.haslayer(ICMP):
        	log_line = f"ICMP Packet: {src_ip} -> {dst_ip}\n"
        	print(log_line.strip())
        elif packet.haslayer(TCP):
        	log_line = f"TCP Packet: {src_ip} -> {dst_ip}\n"
        	print(log_line.strip())
        elif packet.haslayer(UDP):
        	log_line = f"UDP Packet: {src_ip} -> {dst_ip}\n"
        	print(log_line.strip())
        
        
        #Writes the networked traffic to a file called network_log.txt
        with open("network_log.txt", "a") as f:
            f.write(log_line)

print("Starting packet capture... Press Ctrl+C to stop.")
# Change the BPF filter to listen for icmp
sniff(filter="icmp or tcp or udp", prn=packet_callback, count=10)
