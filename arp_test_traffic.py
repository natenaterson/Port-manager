#!/usr/bin/env python3
"""
arp_test_traffic.py

Builds a fixed set of fabricated ARP packets, one of which imitates ARP
spoofing, for testing an ARP-spoof detector. Everything is fake: made-up
MAC addresses and a private 192.168.56.0/24 range.

This is meant to test the arp monitor it is written by claude.

Modes:
  --pcap FILE    write the packets to a pcap file (nothing is sent anywhere)
  --iface IFACE  send the packets on a virtual interface (veth*/dummy* only)
"""
import argparse
import sys
import time

from scapy.all import ARP, ICMP, IP, Ether, sendp, wrpcap

BROADCAST = "ff:ff:ff:ff:ff:ff"
ZERO_MAC = "00:00:00:00:00:00"

GW_IP, GW_MAC = "192.168.56.1", "02:00:00:00:00:01"
HOST_IP, HOST_MAC = "192.168.56.20", "02:00:00:00:00:20"
ATTACKER_MAC = "02:00:00:00:00:66"
PROBE_MAC = "02:00:00:00:00:50"


def make_arp(op, hwsrc, psrc, pdst, hwdst=ZERO_MAC, eth_src=None, eth_dst=None):
    """Build an Ethernet+ARP packet. op: 1 = request, 2 = reply."""
    if eth_dst is None:
        eth_dst = BROADCAST if op == 1 else hwdst
    return Ether(src=eth_src or hwsrc, dst=eth_dst) / ARP(
        op=op, hwsrc=hwsrc, psrc=psrc, hwdst=hwdst, pdst=pdst
    )


def build_scenario():
    """
    Returns a list of (label, packet, expect_alert).
    expect_alert is True, False, or None (None = depends on your design).
    """
    return [
        ("Gateway replies to host (first sighting of gateway)",
         make_arp(2, GW_MAC, GW_IP, HOST_IP, hwdst=HOST_MAC), False),

        ("Host asks who has the gateway (first sighting of host)",
         make_arp(1, HOST_MAC, HOST_IP, GW_IP), False),

        ("Gateway replies again with the same MAC (normal repeat)",
         make_arp(2, GW_MAC, GW_IP, HOST_IP, hwdst=HOST_MAC), False),

        ("ARP probe from 0.0.0.0 (should be ignored)",
         make_arp(1, PROBE_MAC, "0.0.0.0", "192.168.56.50"), False),

        ("SPOOF: reply claims the gateway IP is at the attacker's MAC",
         make_arp(2, ATTACKER_MAC, GW_IP, HOST_IP, hwdst=HOST_MAC), True),

        ("SPOOF repeated (alert or suppressed, depending on your dedupe)",
         make_arp(2, ATTACKER_MAC, GW_IP, HOST_IP, hwdst=HOST_MAC), None),

        ("Ethernet source differs from ARP sender MAC (only if you built that rule)",
         make_arp(2, HOST_MAC, HOST_IP, GW_IP, hwdst=GW_MAC,
                  eth_src=ATTACKER_MAC), None),

        ("Plain ICMP packet (must not trigger any ARP logic)",
         Ether(src=HOST_MAC, dst=GW_MAC) / IP(src=HOST_IP, dst=GW_IP) / ICMP(),
         False),
    ]


def expectation_text(expect):
    if expect is True:
        return "EXPECT: ALERT"
    if expect is False:
        return "EXPECT: no alert"
    return "EXPECT: depends on your design"


def main():
    parser = argparse.ArgumentParser(description="Generate fake ARP test traffic.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--pcap", metavar="FILE", help="write packets to a pcap file")
    group.add_argument("--iface", metavar="IFACE",
                       help="send packets on a virtual interface (veth*/dummy*)")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="seconds between packets in --iface mode (default 1.0)")
    args = parser.parse_args()

    scenario = build_scenario()

    if args.pcap:
        wrpcap(args.pcap, [pkt for _, pkt, _ in scenario])
        print(f"Wrote {len(scenario)} packets to {args.pcap}. Packet order:")
        for number, (label, _, expect) in enumerate(scenario, start=1):
            print(f"  [{number}] {label}  ({expectation_text(expect)})")
        return

    # Safety guard: these packets claim to be a gateway. On a real network
    # that would genuinely disrupt other devices, so only allow virtual links.
    if not args.iface.startswith(("veth", "dummy")):
        sys.exit("Refusing to send: --iface must be a virtual interface "
                 "(name starting with 'veth' or 'dummy').")

    for number, (label, pkt, expect) in enumerate(scenario, start=1):
        print(f"[{number}] {label}  ({expectation_text(expect)})")
        sendp(pkt, iface=args.iface, verbose=False)
        time.sleep(args.delay)


if __name__ == "__main__":
    main()
