"""Detection rules that turn PacketEvent objects into Alerts.

Each rule counts initiating TCP SYNs inside a sliding time window:
- port_scan: one source reaches many distinct ports on one destination.
- repeated_syn: one source keeps opening connections to the same destination port.
- high_connection_rate: optional; one source's SYN rate exceeds a threshold
  derived from a known-normal baseline capture.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque

from .models import Alert, PacketEvent, RuleConfig


class RuleDetector:
    def __init__(self, config: RuleConfig | None = None, baseline_syn_rate: float | None = None):
        self.config = config or RuleConfig()
        self.baseline_syn_rate = baseline_syn_rate
        self._scan = defaultdict(deque)
        self._repeated = defaultdict(deque)
        self._rate = defaultdict(deque)
        self._last_alert: dict[tuple, float] = {}

    def _may_alert(self, rule: str, group: tuple, when: float, cooldown: float) -> bool:
        key = (rule, group)
        prior = self._last_alert.get(key)
        if prior is not None and when - prior < cooldown:
            return False
        self._last_alert[key] = when
        return True

    def process(self, packet: PacketEvent) -> list[Alert]:
        if not packet.tcp_syn or packet.destination_port is None:
            return []

        cfg = self.config
        t = packet.timestamp
        src, dst, port = packet.source, packet.destination, packet.destination_port
        alerts: list[Alert] = []

        scan_key = (src, dst)
        recent_ports = self._scan[scan_key]
        recent_ports.append((t, port))
        while recent_ports and recent_ports[0][0] < t - cfg.scan_seconds:
            recent_ports.popleft()
        unique_ports = len({p for _, p in recent_ports})
        if unique_ports >= cfg.scan_ports and self._may_alert(
            "port_scan", scan_key, t, cfg.scan_seconds
        ):
            alerts.append(Alert(
                rule="port_scan", source=src, destination=dst, timestamp=t,
                observed=unique_ports, threshold=cfg.scan_ports,
                window_seconds=cfg.scan_seconds,
                detail=f"TCP SYN packets to {unique_ports} distinct destination ports",
            ))

        repeat_key = (src, dst, port)
        recent_syns = self._repeated[repeat_key]
        recent_syns.append(t)
        while recent_syns and recent_syns[0] < t - cfg.repeated_seconds:
            recent_syns.popleft()
        if len(recent_syns) >= cfg.repeated_syns and self._may_alert(
            "repeated_syn", repeat_key, t, cfg.repeated_seconds
        ):
            alerts.append(Alert(
                rule="repeated_syn", source=src, destination=dst, timestamp=t,
                observed=len(recent_syns), threshold=cfg.repeated_syns,
                window_seconds=cfg.repeated_seconds,
                detail=f"Repeated TCP SYN attempts to destination port {port}",
            ))

        # Optional baseline-dependent heuristic. It is not a standalone attack label.
        if self.baseline_syn_rate is not None:
            threshold = max(
                cfg.min_high_rate_count,
                math.ceil(self.baseline_syn_rate * cfg.rate_window_seconds * cfg.rate_multiplier),
            )
            rate_key = (src,)
            recent_rate = self._rate[rate_key]
            recent_rate.append(t)
            while recent_rate and recent_rate[0] < t - cfg.rate_window_seconds:
                recent_rate.popleft()
            if len(recent_rate) >= threshold and self._may_alert(
                "high_connection_rate", rate_key, t, cfg.rate_window_seconds
            ):
                alerts.append(Alert(
                    rule="high_connection_rate", source=src,
                    destination="multiple/see capture", timestamp=t,
                    observed=len(recent_rate), threshold=threshold,
                    window_seconds=cfg.rate_window_seconds,
                    detail="TCP SYN rate exceeds the baseline-derived threshold",
                ))
        return alerts
