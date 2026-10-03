from scapy.all import ARP, Ether

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
	
	if packet.haslayer(Ether) and packet[Ether].src.lower() != mac:
		return [f"alert {packet_IP} the mac is {mac} the ethernet is {packet[Ether].src.lower()}"]
	
	if packet_IP in IP_to_MAC:
		if IP_to_MAC[packet_IP] != mac:
			if mac in alerts.get(packet_IP, ()):
				return []
			else:
				alerts[packet_IP] = alerts.get(packet_IP, ()) + (mac,)
				return [f"alert {packet_IP} old mac {IP_to_MAC[packet_IP]} new mac: {mac}"]
	else:
		IP_to_MAC[packet_IP] = mac
	return []

def reset_arp_state():
	IP_to_MAC.clear()
	alerts.clear()
