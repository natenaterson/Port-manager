"""
arp_monitor.py
Looks at ARP packets and reports signs of ARP spoofing.
This is written by Nate Montgomery with guidance from Claude.
 
Two things are checked for every ARP packet:
  1. An IP address that is now claimed by a different MAC address than the
     one it was first seen with.
  2. An ARP packet whose Ethernet source MAC differs from the MAC the ARP
     message says it came from.
 
The first MAC seen for an IP is trusted ("trust on first use"). If a spoofer
is already active when the program starts, that first sighting could be a lie.
 
check_arp() only returns messages. It never prints or logs, so it can be
tested on its own and used by packet_sniffer.py.
"""
from scapy.all import ARP, Ether

# IP address -> the MAC address it was first seen with.
ip_to_mac = {}

# IP address -> tuple of all the MACs that were already reported for the IP.
reported_changes = {}
 
# (IP, Ethernet source MAC, ARP sender MAC) combinations already reported.
reported_mismatches = set()
 
 
def check_arp(packet):
    """
    Check one packet and return a list of alert strings.
    An empty list means nothing suspicious was found.
    """
    if not packet.haslayer(ARP):
        return []
 
    arp = packet[ARP]
    ip = arp.psrc
    mac = arp.hwsrc.lower()
 
    # 0.0.0.0 means the sender is checking if an address is free (an ARP
    # probe). That is normal and says nothing about who owns an IP.
    if ip == "0.0.0.0":
        return []
 
    found = []
 
    # The Ethernet header and the ARP message should agree on who
    # sent the packet. The Ether layer is missing on some captures.
    if packet.haslayer(Ether):
        ethernet_mac = packet[Ether].src.lower()
        key = (ip, ethernet_mac, mac)
        if ethernet_mac != mac and key not in reported_mismatches:
            reported_mismatches.add(key)
            found.append(
                f"Ethernet source {ethernet_mac} does not match ARP sender "
                f"{mac} for IP {ip}"
            )
 
    # An IP address that is suddenly claimed by a different MAC.
    known_mac = ip_to_mac.get(ip)
    if known_mac is None:
        ip_to_mac[ip] = mac
    elif known_mac != mac and mac not in reported_changes.get(ip, ()):
        reported_changes[ip] = reported_changes.get(ip, ()) + (mac,)
        found.append(
            f"IP {ip} changed from MAC {known_mac} to MAC {mac} "
            f"(possible ARP spoofing)"
        )
 
    return found

def reset_arp_state():
    """Forget everything that was learned. Used by the tests."""
    ip_to_mac.clear()
    reported_changes.clear()
    reported_mismatches.clear()
