import unittest
from evaluate import evaluate


class EvaluateTests(unittest.TestCase):
    def test_expected_results(self):
        rows, counts = evaluate({"results": [
            {"capture": "network-traffic-1.pcapng", "alerts": []},
            {"capture": "traffic-many-ports.pcapng", "alerts": [{"rule": "port_scan"}]},
            {"capture": "traffic-repeated-connection.pcapng", "alerts": [{"rule": "repeated_syn"}]},
        ]})
        self.assertEqual(len(rows), 3)
        self.assertEqual(counts, {"TP": 2, "FP": 0, "TN": 1, "FN": 0})

    def test_missing_detection_and_normal_false_alarm(self):
        _, counts = evaluate({"results": [
            {"capture": "network-traffic-1.pcapng", "alerts": [{"rule": "port_scan"}]},
            {"capture": "traffic-repeated-connection.pcapng", "alerts": []},
        ]})
        self.assertEqual(counts, {"TP": 0, "FP": 1, "TN": 0, "FN": 1})


if __name__ == "__main__":
    unittest.main()
