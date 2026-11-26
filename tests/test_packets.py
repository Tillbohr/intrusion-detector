"""Mocked parser contract tests; actual Scapy/PCAP integration must be tested separately."""
from __future__ import annotations

import sys
import types
import unittest
from unittest.mock import patch

from cache_ids.packets import packet_to_event, read_capture


class FakeLayer:
    def __init__(self, **attrs):
        self.__dict__.update(attrs)


class FakePacket:
    def __init__(self, mapping, timestamp):
        self.mapping = mapping
        self.time = timestamp

    def __contains__(self, layer):
        return layer in self.mapping

    def __getitem__(self, layer):
        return self.mapping[layer]


class ParserTests(unittest.TestCase):
    def setUp(self):
        self.ip, self.ipv6, self.tcp, self.udp = (type(name, (), {}) for name in ("IP", "IPv6", "TCP", "UDP"))
        module = types.ModuleType("scapy.all")
        module.IP, module.IPv6, module.TCP, module.UDP = self.ip, self.ipv6, self.tcp, self.udp
        self.mock_modules = patch.dict(sys.modules, {
            "scapy": types.ModuleType("scapy"), "scapy.all": module,
        })
        self.mock_modules.start()
        self.addCleanup(self.mock_modules.stop)

    def test_ipv4_syn_request(self):
        packet = FakePacket({self.ip: FakeLayer(src="1.2.3.4", dst="5.6.7.8"),
                             self.tcp: FakeLayer(sport=1000, dport=22, flags=0x02)}, 1.5)
        event = packet_to_event(packet)
        self.assertTrue(event.tcp_syn)
        self.assertEqual((event.ip_version, event.destination_port), (4, 22))

    def test_syn_ack_is_not_initiating(self):
        packet = FakePacket({self.ip: FakeLayer(src="a", dst="b"),
                             self.tcp: FakeLayer(sport=22, dport=1000, flags=0x12)}, 2)
        self.assertFalse(packet_to_event(packet).tcp_syn)

    def test_ipv6_udp_is_retained(self):
        packet = FakePacket({self.ipv6: FakeLayer(src="::1", dst="::2"),
                             self.udp: FakeLayer(sport=500, dport=53)}, 3)
        event = packet_to_event(packet)
        self.assertEqual((event.ip_version, event.protocol, event.destination_port), (6, "UDP", 53))

    def test_non_ip_packets_skipped(self):
        self.assertIsNone(packet_to_event(FakePacket({}, 4)))

    def test_missing_path_raises_file_not_found_before_scapy_import(self):
        with self.assertRaises(FileNotFoundError):
            list(read_capture("no_such_capture_ee21.pcapng"))


if __name__ == "__main__":
    unittest.main()
