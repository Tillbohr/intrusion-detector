"""Run captures through the parser and rule detector, then save the results."""

from __future__ import annotations

import csv
import json
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

from .models import PacketEvent, RuleConfig
from .packets import read_capture
from .rules import RuleDetector


# Reader injection allows end-to-end runner tests without Scapy or PCAP files.
Reader = Callable[[str | Path], Iterable[PacketEvent]]


def readable_time(timestamp: float) -> str:
    """Format a capture timestamp as local date and time with milliseconds.

    Matches Wireshark's "Date and Time of Day" column on the same computer,
    so an alert can be found in Wireshark by its time. Windows cannot convert
    times near 1970 to local time (devices without a clock record those), so
    those fall back to UTC.
    """
    try:
        moment = datetime.fromtimestamp(timestamp).astimezone()
    except (OSError, OverflowError, ValueError):
        moment = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return moment.isoformat(sep=" ", timespec="milliseconds")


def estimate_baseline(path: str | Path, reader: Reader = read_capture) -> dict:
    """Estimate a simple global initiating-SYN rate from a known-normal capture.

    The baseline is environment-dependent, not an established security limit.
    """
    total = syns = 0
    first = last = None
    for event in reader(path):
        total += 1
        syns += int(event.tcp_syn)
        first = event.timestamp if first is None else min(first, event.timestamp)
        last = event.timestamp if last is None else max(last, event.timestamp)
    duration = last - first if first is not None and last is not None else 0.0
    return {
        "capture": str(path), "ip_packets": total, "initial_syns": syns,
        "duration_seconds": round(duration, 3),
        "syns_per_second": round(syns / duration, 6) if duration > 0 else 0.0,
    }


def analyze_capture(
    path: str | Path,
    config: RuleConfig | None = None,
    baseline_syn_rate: float | None = None,
    reader: Reader = read_capture,
) -> dict:
    """Analyze one saved capture; report measurements, never invented detections."""
    detector = RuleDetector(config, baseline_syn_rate)
    counts = {"ip_packets": 0, "ipv4_packets": 0, "ipv6_packets": 0,
              "tcp_packets": 0, "udp_packets": 0, "initial_syns": 0}
    alerts = []
    first = last = None
    started = time.perf_counter()
    for packet in reader(path):
        counts["ip_packets"] += 1
        if packet.ip_version == 4:
            counts["ipv4_packets"] += 1
        elif packet.ip_version == 6:
            counts["ipv6_packets"] += 1
        if packet.protocol == "TCP":
            counts["tcp_packets"] += 1
        elif packet.protocol == "UDP":
            counts["udp_packets"] += 1
        counts["initial_syns"] += int(packet.tcp_syn)
        first = packet.timestamp if first is None else min(first, packet.timestamp)
        last = packet.timestamp if last is None else max(last, packet.timestamp)
        alerts.extend(detector.process(packet))
    duration = time.perf_counter() - started
    rules = ("port_scan", "repeated_syn", "high_connection_rate")
    return {
        "capture": str(path), **counts,
        "capture_duration_seconds": round(last - first, 3) if first is not None and last is not None else 0,
        "processing_seconds": round(duration, 3),
        "throughput_ip_packets_per_second": round(counts["ip_packets"] / duration, 1)
        if duration > 0 else None,
        "rule_counts": {rule: sum(a.rule == rule for a in alerts) for rule in rules},
        "alerts": [{**asdict(alert), "time": readable_time(alert.timestamp)}
                   for alert in alerts],
    }


def write_results(results: list[dict], config: RuleConfig, baseline: dict | None,
                  json_path: str | Path, csv_path: str | Path,
                  errors: list[dict] | None = None) -> None:
    """Export a machine-readable summary and one alert per CSV row.

    `errors` lists captures that could not be read. They are kept apart from
    `results` so evaluate.py never mistakes an unreadable capture for one that
    was analyzed and produced no alerts.
    """
    Path(json_path).parent.mkdir(parents=True, exist_ok=True)
    Path(csv_path).parent.mkdir(parents=True, exist_ok=True)
    payload = {"config": asdict(config), "baseline": baseline,
               "results": results, "errors": errors or []}
    Path(json_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    columns = ["capture", "rule", "source", "destination", "time", "timestamp",
               "observed", "threshold", "window_seconds", "detail"]
    with Path(csv_path).open("w", newline="", encoding="utf-8") as out:
        writer = csv.DictWriter(out, fieldnames=columns)
        writer.writeheader()
        for result in results:
            for alert in result["alerts"]:
                writer.writerow({"capture": result["capture"], **alert})
