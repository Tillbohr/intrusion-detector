import csv
import json
import tempfile
import unittest
from pathlib import Path

from cache_ids.models import PacketEvent
from cache_ids.runner import analyze_capture, estimate_baseline, write_results
from cache_ids.models import RuleConfig


def make_reader(events):
    return lambda path: iter(events)


class RunnerTests(unittest.TestCase):
    def test_baseline_uses_timestamp_span_not_processing_time(self):
        ev = [PacketEvent(10, "a", "b", "TCP", 22, True),
              PacketEvent(12, "a", "b", "TCP", 23, False),
              PacketEvent(20, "a", "b", "TCP", 24, True)]
        info = estimate_baseline("normal.pcapng", reader=make_reader(ev))
        self.assertEqual(info["ip_packets"], 3)
        self.assertEqual(info["initial_syns"], 2)
        self.assertAlmostEqual(info["syns_per_second"], 0.2)

    def test_runner_counts_and_reports_real_events(self):
        ev = [PacketEvent(i / 100, "192.168.56.1", "192.168.56.101", "TCP", i + 20, True, 45000, 4)
              for i in range(20)]
        result = analyze_capture("scan.pcapng", reader=make_reader(ev))
        self.assertEqual(result["ip_packets"], 20)
        self.assertEqual(result["tcp_packets"], 20)
        self.assertEqual(result["ipv4_packets"], 20)
        self.assertEqual(result["initial_syns"], 20)
        self.assertEqual(result["rule_counts"]["port_scan"], 1)

    def test_json_and_csv_are_written(self):
        ev = [PacketEvent(i/100, "a", "b", "TCP", i + 20, True) for i in range(20)]
        result = analyze_capture("scan.pcapng", reader=make_reader(ev))
        with tempfile.TemporaryDirectory() as tmp:
            json_name = Path(tmp) / "outputs" / "results.json"
            csv_name = Path(tmp) / "outputs" / "alerts.csv"
            write_results([result], RuleConfig(), None, json_name, csv_name)
            payload = json.loads(json_name.read_text())
            self.assertEqual(len(payload["results"][0]["alerts"]), 1)
            with csv_name.open(newline="") as f:
                rows = list(csv.DictReader(f))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["rule"], "port_scan")

    def test_empty_capture(self):
        result = analyze_capture("empty.pcapng", reader=make_reader([]))
        self.assertEqual(result["ip_packets"], 0)
        self.assertEqual(result["alerts"], [])
        self.assertEqual(result["capture_duration_seconds"], 0)


if __name__ == "__main__":
    unittest.main()
