from scapy.all import IP, ICMP, sniff, TCP, UDP

ICMP_count =0
TCP_count = 0
UDP_count = 0

def packet_callback(packet):
    # Check for IP and (ICMP (Ping) or TCP or UDP) 
    #ICMP is networking Layer 3
    #TCP is reliabble data Layer 4. Eg text, email
    #UDP is fast Layer 4. Eg video, streaming
    if packet.haslayer(IP) and (packet.haslayer(ICMP) or packet.haslayer(TCP) or packet.haslayer(UDP)):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        global ICMP_count
        global TCP_count
        global UDP_count
        
        if packet.haslayer(ICMP):
        	log_line = f"ICMP Packet: {src_ip} -> {dst_ip}\n"
        	print(log_line.strip())
        	ICMP_count += 1
        elif packet.haslayer(TCP):
        	log_line = f"TCP Packet: {src_ip} -> {dst_ip}\n"
        	print(log_line.strip())
        	TCP_count += 1
        elif packet.haslayer(UDP):
        	log_line = f"UDP Packet: {src_ip} -> {dst_ip}\n"
        	print(log_line.strip())
        	UDP_count += 1
        
        
        #Writes the networked traffic to a file called network_log.txt
        with open("network_log.txt", "a") as f:
            f.write(log_line)

print("Starting packet capture... Press Ctrl+C to stop.")
# Change the BPF filter to listen for icmp
packet_count = int(input("Please Enter the number of packets you want to track: "))
sniff(filter="icmp or tcp or udp", prn=packet_callback, count=packet_count)


print("=" * 20, "Capture Summary", "=" * 20)
print()
print("Total packet: ", (ICMP_count + TCP_count + UDP_count))
print()
print("ICMP: ", ICMP_count)
print("TCP: ", TCP_count)
print("UDP: ", UDP_count)
print()
print("=" * 58)
