from scapy.all import ARP

IP_to_MAC = {}

alerts = {}

def check_arp(packet):
	if not packet.haslayer(ARP):
		return []
	packet_arp = packet[ARP]
	
	if packet_arp.psrc == "0.0.0.0":
		return []
	
	mac = packet_arp.hwsrc
	mac = mac.lower()
	
	packet_IP = packet_arp.psrc
	
	if packet_IP in IP_to_MAC:
		if IP_to_MAC[packet_IP] != mac:
			if MAC in alerts.get(packet_IP, ()):
				return []
			else:
				alerts[packet_IP] = alerts.get(packet_IP, ()) + (mac,)
				return [f"alert {packet_IP} old mac {IP_to_MAC[IP]} new mac: {MAC}"]
	else:
		IP_to_MAC[packet_IP] = mac
		return []

def reset_arp_state():
	IP_to_MAC.clear()
	alerts.clear()
