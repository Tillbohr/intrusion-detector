"""Melvin's component: stream saved PCAP/PCAPNG captures into PacketEvent objects.

All capture reading happens here. There is intentionally NO live-sniffing code.
Scapy is imported lazily so rule and runner tests can run without Scapy.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from .models import PacketEvent


def packet_to_event(packet: object) -> PacketEvent | None:
    """Convert one Scapy packet to a stable event, or skip non-IP packets.

    Initiating TCP SYN packets are SYN=1 and ACK=0. SYN+ACK replies are not
    counted as new connection attempts. UDP/other IP packets remain available
    to the analyzer, although the initial detection rules use TCP SYNs.
    """
    try:
        from scapy.all import IP, IPv6, TCP, UDP
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is missing. Run: python -m pip install -r requirements.txt"
        ) from exc

    if IP in packet:
        network = packet[IP]
        version = 4
    elif IPv6 in packet:
        network = packet[IPv6]
        version = 6
    else:
        return None

    if TCP in packet:
        transport = packet[TCP]
        flags = int(transport.flags)
        protocol = "TCP"
        initiating_syn = bool(flags & 0x02) and not bool(flags & 0x10)
        source_port = int(transport.sport)
        destination_port = int(transport.dport)
    elif UDP in packet:
        transport = packet[UDP]
        protocol = "UDP"
        initiating_syn = False
        source_port = int(transport.sport)
        destination_port = int(transport.dport)
    else:
        protocol = "OTHER_IP"
        initiating_syn = False
        source_port = None
        destination_port = None

    return PacketEvent(
        timestamp=float(packet.time),
        source=str(network.src),
        destination=str(network.dst),
        protocol=protocol,
        destination_port=destination_port,
        tcp_syn=initiating_syn,
        source_port=source_port,
        ip_version=version,
    )


def read_capture(path: str | Path) -> Iterator[PacketEvent]:
    """Yield IP packet events in capture order without loading whole files.

    Raises FileNotFoundError for missing captures and RuntimeError when Scapy
    is not installed. Truncated or invalid captures raise parser errors.
    """
    capture_path = Path(path)
    if not capture_path.is_file():
        raise FileNotFoundError(f"Capture file not found: {capture_path}")

    try:
        from scapy.all import PcapReader
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is missing. Run: python -m pip install -r requirements.txt"
        ) from exc

    with PcapReader(str(capture_path)) as reader:
        for packet in reader:
            event = packet_to_event(packet)
            if event is not None:
                yield event
