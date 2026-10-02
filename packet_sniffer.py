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
        	log_line = f"TCP Packet: {src_ip} -> {dst_ip} | flag: {Explain_flags(packet[TCP].flags)}\n"
        	print(log_line.strip())
        	TCP_count += 1
        elif packet.haslayer(UDP):
        	log_line = f"UDP Packet: {src_ip} -> {dst_ip}\n"
        	print(log_line.strip())
        	UDP_count += 1
        
        
        #Writes the networked traffic to a file called network_log.txt
        with open("network_log.txt", "a") as f:
            f.write(log_line)

def Explain_flags(flag):
	match flag:
		case "S":
			#Starts a 3 way handshake
			return "Synchronize"
		case "A":
			#Confirms a packet or data was succesefully sent
			return "Acknowledgment"
		case "SA":
			#Synchronize and Acknowledges
			return "Synchronize and Acknowledges"
		case "PA":
			#Push and Acknowledgment
			#Tells the reciver to process data
			return "Push and Acknowledgment"
		case "FA":
			#Finish and Acknowledgment
			#Signals that one side is clsoing the connection
			return "Finish and Acknowledgment"
		case "F":
			#Connection is closing
			return "Finish"
		case "R":
			#Abort a connection due to error
			return "Reset"
		case "P":
			#Push data to the application layer
			return "Push"
		case "U":
			#Urgent pointer field is valid
			return "Urgent"
		case "E":
			#Signals that the host is Explicit Congestion Notification capable or has recived a congestion notifcation
			return "ECN-Echo"
		case "C":
			#Acknoledges the echo
			return "Congestion Window Reduced"
		case "N":
			#Protection against hidden or malicious concealment of congestion signals
			return "Nonce Sum"
print("Starting packet capture... Press Ctrl+C to stop.")
packet_count = int(input("Please Enter the number of packets you want to track: "))
# Change the BPF filter to listen for ICMP, TCP, or UDP
sniff(filter="icmp or tcp or udp", prn=packet_callback, count=packet_count)

#Prints the capture summary
print("=" * 20, "Capture Summary", "=" * 20)
print()
print("Total packet: ", (ICMP_count + TCP_count + UDP_count))
print()
print("ICMP: ", ICMP_count)
print("TCP: ", TCP_count)
print("UDP: ", UDP_count)
print()
print("=" * 58)
