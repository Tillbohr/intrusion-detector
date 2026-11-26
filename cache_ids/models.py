"""Shared data contracts for packet parsing and rule detection.

Melvin owns parser/runner integration; Kaleb can modify rules.py independently.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PacketEvent:
    timestamp: float
    source: str
    destination: str
    protocol: str
    destination_port: int | None = None
    tcp_syn: bool = False
    source_port: int | None = None
    ip_version: int | None = None


@dataclass(frozen=True)
class Alert:
    rule: str
    source: str
    destination: str
    timestamp: float
    observed: int
    threshold: int
    window_seconds: int
    detail: str


@dataclass(frozen=True)
class RuleConfig:
    # Proposed Milestone 2 thresholds. They have NOT been calibrated against PCAPs.
    scan_ports: int = 20
    scan_seconds: int = 10
    repeated_syns: int = 30
    repeated_seconds: int = 60
    rate_window_seconds: int = 10
    rate_multiplier: float = 3.0
    min_high_rate_count: int = 30
