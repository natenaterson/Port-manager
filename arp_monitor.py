from scapy.all import ARP, Ether, IP

IP_to_MAC = {
	"IP" : ,
	"MAC" : 
}

alerts = {
	"IP" :,
	"MAC":
}

def packet_alerts(packet):
	if packet != packet.haslayer(ARP):
		return
	packet_arp = packet[ARP]
	
	if packet_arp.psrc == "0.0.0.0":
		return "no alert"
	
	MAC = packet['Ether'].src
	MAC = MAC.lower()
	
	packet_IP = packet_arp.prsc
	
	if packet_IP in IP_to_MAC:
		if IP_to_MAC[packet_IP] != MAC:
			return "alert {packet_IP} old mac {IP_to_MAC[IP]} new mac: {MAC}"
	else:
		IP_to_MAC[packet_IP] = MAC
			
