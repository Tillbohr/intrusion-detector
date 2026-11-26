"""Rule tests are synthetic and do not establish performance on real captures."""
import unittest

from cache_ids.models import PacketEvent, RuleConfig
from cache_ids.rules import RuleDetector


def syn(t, port, src="192.168.56.1", dst="192.168.56.101"):
    return PacketEvent(t, src, dst, "TCP", port, True, 45000, 4)


class RuleTests(unittest.TestCase):
    def test_port_scan_detects_twenty_distinct_ports(self):
        det = RuleDetector()
        alerts = [a for i in range(20) for a in det.process(syn(i / 10, 1000 + i))]
        self.assertEqual([a.rule for a in alerts], ["port_scan"])

    def test_repeats_do_not_count_as_scan(self):
        det = RuleDetector()
        alerts = [a for i in range(30) for a in det.process(syn(i, 445))]
        self.assertEqual([a.rule for a in alerts], ["repeated_syn"])

    def test_no_false_alert_for_sparse_syns(self):
        det = RuleDetector()
        alerts = [a for i in range(8) for a in det.process(syn(i * 3, 443))]
        self.assertEqual(alerts, [])

    def test_scanning_outside_window_does_not_count(self):
        det = RuleDetector()
        alerts = [a for i in range(25) for a in det.process(syn(i, 2000 + i))]
        self.assertEqual(alerts, [])

    def test_non_syn_ignored(self):
        det = RuleDetector()
        for i in range(80):
            self.assertFalse(det.process(PacketEvent(i / 10, "1.2.3.4", "5.6.7.8", "UDP", i + 300)))

    def test_optional_rate_only_when_baseline_given(self):
        events = [syn(i / 10, 443) for i in range(30)]
        d1, d2 = RuleDetector(), RuleDetector(baseline_syn_rate=0.3)
        off = [a for p in events for a in d1.process(p)]
        on = [a for p in events for a in d2.process(p)]
        self.assertNotIn("high_connection_rate", [a.rule for a in off])
        self.assertIn("high_connection_rate", [a.rule for a in on])

    def test_cooldown_suppresses_duplicate_alerts(self):
        det = RuleDetector()
        alerts = [a for i in range(50) for a in det.process(syn(i / 10, i + 1000))]
        self.assertEqual(sum(a.rule == "port_scan" for a in alerts), 1)

    def test_custom_threshold(self):
        det = RuleDetector(RuleConfig(scan_ports=3))
        alerts = [a for i in range(3) for a in det.process(syn(i / 10, 800 + i))]
        self.assertEqual([a.rule for a in alerts], ["port_scan"])


if __name__ == "__main__":
    unittest.main()
