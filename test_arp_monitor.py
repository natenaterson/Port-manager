"""
test_arp_monitor.py

Run with:  python3 -m unittest -v test_arp_monitor

This is meant to test the arp monitor it is written by claude.

Assumes packet_sniffer.py provides:
    check_arp(packet)   -> list of alert strings ([] means no alert)
    reset_arp_state()   -> clears the IP->MAC table and alert bookkeeping
and that its capture code is under  if __name__ == "__main__":
"""
import unittest

from scapy.all import ICMP, IP, Ether

import packet_sniffer as ps
from arp_test_traffic import (
    ATTACKER_MAC, GW_IP, GW_MAC, HOST_IP, HOST_MAC, PROBE_MAC,
    build_scenario, make_arp,
)

check_arp = ps.check_arp
reset = ps.reset_arp_state


def gw_reply(mac=GW_MAC):
    return make_arp(2, mac, GW_IP, HOST_IP, hwdst=HOST_MAC)


class ArpMonitorTests(unittest.TestCase):
    def setUp(self):
        reset()  # every test starts with an empty table

    def test_first_sighting_does_not_alert(self):
        self.assertEqual(check_arp(gw_reply()), [])

    def test_same_mapping_repeated_does_not_alert(self):
        check_arp(gw_reply())
        self.assertEqual(check_arp(gw_reply()), [])

    def test_mac_change_alerts_and_names_both_macs(self):
        check_arp(gw_reply())
        alerts = check_arp(gw_reply(ATTACKER_MAC))
        self.assertTrue(alerts, "expected an alert for a changed MAC")
        text = " ".join(alerts).lower()
        self.assertIn(GW_IP, text)
        self.assertIn(GW_MAC, text)
        self.assertIn(ATTACKER_MAC, text)

    def test_spoofed_request_is_also_checked(self):
        # Learn the host from a normal request, then someone else claims its IP.
        check_arp(make_arp(1, HOST_MAC, HOST_IP, GW_IP))
        alerts = check_arp(make_arp(1, ATTACKER_MAC, HOST_IP, GW_IP))
        self.assertTrue(alerts)

    def test_probe_from_zero_address_is_ignored(self):
        self.assertEqual(check_arp(make_arp(1, PROBE_MAC, "0.0.0.0", "192.168.56.50")), [])
        # a second probe with a different MAC must not look like a conflict
        self.assertEqual(check_arp(make_arp(1, ATTACKER_MAC, "0.0.0.0", "192.168.56.50")), [])

    def test_mac_case_is_normalized(self):
        check_arp(gw_reply(GW_MAC.upper()))
        self.assertEqual(check_arp(gw_reply(GW_MAC.lower())), [])

    def test_non_arp_packet_is_ignored(self):
        pkt = Ether(src=HOST_MAC, dst=GW_MAC) / IP(src=HOST_IP, dst=GW_IP) / ICMP()
        self.assertEqual(check_arp(pkt), [])

    def test_ethernet_source_mismatch(self):
        # DELETE this test if you did not implement the Ethernet-vs-ARP rule.
        check_arp(make_arp(1, HOST_MAC, HOST_IP, GW_IP))
        pkt = make_arp(2, HOST_MAC, HOST_IP, GW_IP, hwdst=GW_MAC, eth_src=ATTACKER_MAC)
        self.assertTrue(check_arp(pkt))

    def test_full_scenario_in_order(self):
        for number, (label, pkt, expect) in enumerate(build_scenario(), start=1):
            with self.subTest(step=number, label=label):
                alerts = check_arp(pkt)
                if expect is True:
                    self.assertTrue(alerts, "expected an alert")
                elif expect is False:
                    self.assertEqual(alerts, [], f"unexpected alert: {alerts}")


if __name__ == "__main__":
    unittest.main()
