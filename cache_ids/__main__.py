"""Command-line entry point. Run with: python -m cache_ids --pcap path/to/capture.pcapng"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .models import RuleConfig
from .packets import CaptureError, require_scapy
from .runner import analyze_capture, estimate_baseline, write_results

MAX_ALERTS_SHOWN = 12


def positive_int(raw: str) -> int:
    val = int(raw)
    if val <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return val


def print_summary(capture: str, result: dict) -> None:
    print(f"\n{Path(capture).name}: {result['ip_packets']} IP packets, "
          f"{result['initial_syns']} initiating SYNs, "
          f"{len(result['alerts'])} alerts, "
          f"{result['processing_seconds']:.3f}s processing")
    for alert in result["alerts"][:MAX_ALERTS_SHOWN]:
        print(f"  {alert['time']} | {alert['rule']} | "
              f"{alert['source']} -> {alert['destination']} | "
              f"observed {alert['observed']} (threshold {alert['threshold']})")
    hidden = len(result["alerts"]) - MAX_ALERTS_SHOWN
    if hidden > 0:
        print(f"  ... {hidden} more alerts in the output files")


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

    # These problems stop the whole run: Scapy is missing or the baseline is unreadable.
    try:
        require_scapy()
        baseline = estimate_baseline(args.baseline) if args.baseline else None
    except (RuntimeError, CaptureError, OSError) as err:
        print(f"Error: {err}", file=sys.stderr)
        return 1
    if baseline:
        print(f"Baseline: {baseline['initial_syns']} initiating SYNs over "
              f"{baseline['duration_seconds']} seconds")

    # An unreadable capture is reported and skipped so the others still run.
    results, errors = [], []
    for capture in args.pcap:
        try:
            result = analyze_capture(
                capture, cfg, baseline["syns_per_second"] if baseline else None
            )
        except (CaptureError, OSError) as err:
            errors.append({"capture": capture, "error": str(err)})
            print(f"\nSkipped: {err}", file=sys.stderr)
            continue
        results.append(result)
        print_summary(capture, result)

    try:
        write_results(results, cfg, baseline, args.json_out, args.csv_out, errors)
    except OSError as err:
        print(f"Error: could not save results: {err}", file=sys.stderr)
        return 1
    print(f"\nSaved JSON: {args.json_out}\nSaved CSV: {args.csv_out}")
    if errors:
        print(f"{len(errors)} capture(s) could not be read; see \"errors\" in {args.json_out}",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
