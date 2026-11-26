"""Run with: python -m cache_ids --pcap path/to/capture.pcapng"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .models import RuleConfig
from .runner import analyze_capture, estimate_baseline, write_results


def positive_int(raw: str) -> int:
    val = int(raw)
    if val <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return val


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Team Cache offline network intrusion detector")
    parser.add_argument("--pcap", nargs="+", required=True, help="Saved PCAP or PCAPNG paths")
    parser.add_argument("--baseline", help="Known-normal capture for optional high-rate rule")
    parser.add_argument("--json-out", default="outputs/results.json")
    parser.add_argument("--csv-out", default="outputs/alerts.csv")
    parser.add_argument("--scan-ports", type=positive_int, default=20)
    parser.add_argument("--scan-seconds", type=positive_int, default=10)
    parser.add_argument("--repeated-syns", type=positive_int, default=30)
    parser.add_argument("--repeated-seconds", type=positive_int, default=60)
    args = parser.parse_args(argv)
    cfg = RuleConfig(scan_ports=args.scan_ports, scan_seconds=args.scan_seconds,
                     repeated_syns=args.repeated_syns, repeated_seconds=args.repeated_seconds)
    for name in [*args.pcap, *([args.baseline] if args.baseline else [])]:
        if not Path(name).is_file():
            parser.error(f"Capture not found: {name}")

    try:
        baseline = estimate_baseline(args.baseline) if args.baseline else None
        if baseline:
            print(f"Baseline: {baseline['initial_syns']} initiating SYNs over "
                  f"{baseline['duration_seconds']} seconds")
        results = []
        for capture in args.pcap:
            result = analyze_capture(
                capture, cfg, baseline["syns_per_second"] if baseline else None
            )
            results.append(result)
            print(f"\n{capture}: {result['ip_packets']} IP packets, "
                  f"{result['initial_syns']} initiating SYNs, "
                  f"{len(result['alerts'])} alerts, "
                  f"{result['processing_seconds']:.3f}s processing")
            for alert in result["alerts"][:12]:
                print(f"  {alert['rule']} | {alert['source']} -> {alert['destination']} "
                      f"| observed {alert['observed']} (threshold {alert['threshold']})")
            if len(result["alerts"]) > 12:
                print(f"  ... {len(result['alerts'])-12} more alerts in output file")
        write_results(results, cfg, baseline, args.json_out, args.csv_out)
    except (RuntimeError, OSError, ValueError) as err:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    print(f"\nSaved JSON: {args.json_out}\nSaved CSV: {args.csv_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
