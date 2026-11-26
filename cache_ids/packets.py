"""Read saved PCAP/PCAPNG captures and convert each packet into a PacketEvent.

This module only reads capture files; it does not sniff live traffic.
Scapy is imported inside the functions so the rule and runner tests can run
without Scapy installed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from .models import PacketEvent

_SCAPY_MISSING = "Scapy is missing. Run: python -m pip install -r requirements.txt"


class CaptureError(ValueError):
    """The file exists, but Scapy cannot read it as a PCAP/PCAPNG capture."""


def require_scapy() -> None:
    """Import Scapy up front.

    Scapy's first import takes most of a second. Calling this before timing
    anything keeps that one-time cost out of the first capture's processing
    time, and a missing install is reported before any work starts.
    """
    try:
        import scapy.all  # noqa: F401
    except ImportError as exc:
        raise RuntimeError(_SCAPY_MISSING) from exc


def packet_to_event(packet: object) -> PacketEvent | None:
    """Convert one Scapy packet to a stable event, or skip non-IP packets.

    Initiating TCP SYN packets are SYN=1 and ACK=0. SYN+ACK replies are not
    counted as new connection attempts. UDP/other IP packets remain available
    to the analyzer, although the initial detection rules use TCP SYNs.
    """
    try:
        from scapy.all import IP, IPv6, TCP, UDP
    except ImportError as exc:
        raise RuntimeError(_SCAPY_MISSING) from exc

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

    Raises FileNotFoundError for a missing file, CaptureError for a file that
    is not a PCAP/PCAPNG capture (wrong format or empty), and RuntimeError
    when Scapy is not installed.

    A capture that was cut off partway does not raise an error: Scapy prints
    a "PcapNg: ..." warning and stops, so only the packets before the damage
    are returned.
    """
    capture_path = Path(path)
    if not capture_path.is_file():
        raise FileNotFoundError(f"Capture file not found: {capture_path}")

    try:
        from scapy.all import PcapReader
        from scapy.error import Scapy_Exception
    except ImportError as exc:
        raise RuntimeError(_SCAPY_MISSING) from exc

    try:
        with PcapReader(str(capture_path)) as reader:
            for packet in reader:
                event = packet_to_event(packet)
                if event is not None:
                    yield event
    except Scapy_Exception as exc:
        raise CaptureError(
            f"{capture_path.name} is not a readable PCAP/PCAPNG capture ({exc})"
        ) from exc
