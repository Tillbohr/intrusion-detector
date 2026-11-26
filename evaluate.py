"""Simple scenario-level evaluation of Team Cache's three labeled captures.

This is not a statistical estimate of production IDS accuracy.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

KNOWN_SCENARIOS = {
    "network-traffic-1.pcapng": None,
    "traffic-many-ports.pcapng": "port_scan",
    "traffic-repeated-connection.pcapng": "repeated_syn",
}


def evaluate(payload: dict) -> tuple[list[dict], dict]:
    rows = []
    counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    for result in payload.get("results", []):
        capture = Path(result["capture"]).name
        if capture not in KNOWN_SCENARIOS:
            continue
        expected = KNOWN_SCENARIOS[capture]
        alert_types = {a["rule"] for a in result["alerts"]}
        if expected is None:
            outcome = "FP" if alert_types else "TN"
        else:
            outcome = "TP" if expected in alert_types else "FN"
        counts[outcome] += 1
        rows.append({
            "capture": capture,
            "expected": expected or "no alerts",
            "observed": ", ".join(sorted(alert_types)) or "no alerts",
            "result": outcome,
        })
    return rows, counts


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate Team Cache capture scenarios")
    parser.add_argument("--results", default="results.json")
    args = parser.parse_args()
    path = Path(args.results)
    if not path.exists():
        parser.error(f"Results not found: {path}. Run detector.py first.")
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows, counts = evaluate(payload)
    for row in rows:
        print(f"{row['capture']}\n  expected: {row['expected']}\n"
              f"  observed: {row['observed']}\n  outcome: {row['result']}")
    print(f"\nCapture-level outcomes: {counts}")
    if not rows:
        print("No known capture filenames were found; no scenario evaluation performed.")
    print("WARNING: Three captures are too few to establish reliable real-world detection accuracy.")


if __name__ == "__main__":
    main()
