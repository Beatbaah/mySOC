"""
pcap/pcap_writer.py — Write captured packets to .pcap files for forensics.

Supports:
  - Ring-buffer dump (current sniffer buffer → pcap)
  - Time-window export (fetch from DB metadata + reconstruct minimal pcap)
  - Per-alert evidence capture
"""

import io
import os
import struct
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from utils.logger import get_logger

log = get_logger(__name__)

PCAP_DIR = Path("pcap_exports")
PCAP_MAGIC   = 0xA1B2C3D4
PCAP_VERSION = (2, 4)
PCAP_SNAPLEN = 65535
PCAP_LINKTYPE_RAW = 101   # raw IP
PCAP_LINKTYPE_ETH = 1


# ── Low-level pcap format ──────────────────────────────────────────────────────

def _global_header(linktype: int = PCAP_LINKTYPE_RAW) -> bytes:
    return struct.pack(
        "<IHHiIII",
        PCAP_MAGIC,
        PCAP_VERSION[0], PCAP_VERSION[1],
        0,           # timezone (UTC)
        0,           # sigfigs
        PCAP_SNAPLEN,
        linktype,
    )


def _packet_record(ts: float, data: bytes) -> bytes:
    ts_sec  = int(ts)
    ts_usec = int((ts - ts_sec) * 1_000_000)
    caplen  = len(data)
    origlen = caplen
    return struct.pack("<IIII", ts_sec, ts_usec, caplen, origlen) + data


def _build_minimal_ip_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    proto: str,
    length: int,
) -> bytes:
    """
    Reconstruct a minimal synthetic IP packet from metadata.
    Real payload is zeroed — this preserves header info for Wireshark.
    """
    import socket

    def ip2b(ip: str) -> bytes:
        try:
            return socket.inet_aton(ip)
        except Exception:
            return b"\x00" * 4

    proto_num = {"TCP": 6, "UDP": 17, "ICMP": 1}.get(proto.upper(), 0)
    payload_len = max(0, length - 20)

    # IP header (20 bytes, no options)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,            # version=4, IHL=5
        0,               # DSCP/ECN
        max(length, 40), # total length
        0,               # identification
        0,               # flags/fragment offset
        64,              # TTL
        proto_num,
        0,               # checksum (zeroed)
        ip2b(src_ip),
        ip2b(dst_ip),
    )

    if proto_num == 6 and payload_len >= 20:
        # Minimal TCP header
        transport = struct.pack(
            "!HHIIBBHHH",
            src_port & 0xFFFF,
            dst_port & 0xFFFF,
            0, 0,          # seq, ack
            0x50,          # data offset
            0x02,          # SYN flag
            65535, 0, 0,   # window, checksum, urgent
        )
    elif proto_num == 17 and payload_len >= 8:
        transport = struct.pack(
            "!HHHH",
            src_port & 0xFFFF,
            dst_port & 0xFFFF,
            max(8, payload_len),
            0,
        )
    else:
        transport = b""

    filler = bytes(max(0, payload_len - len(transport)))
    return ip_header + transport + filler


# ── Public API ─────────────────────────────────────────────────────────────────

def ensure_pcap_dir() -> Path:
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    return PCAP_DIR


def dump_buffer_to_pcap(packets: list, filename: str = "") -> Path:
    """
    Write a list of PacketRecord objects (from sniffer ring buffer) to a .pcap file.
    Returns the path of the written file.
    """
    ensure_pcap_dir()
    if not filename:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"capture_{ts}.pcap"

    path = PCAP_DIR / filename
    buf  = io.BytesIO()
    buf.write(_global_header(PCAP_LINKTYPE_RAW))

    written = 0
    for pkt in packets:
        try:
            # Use real payload if available, else reconstruct
            if hasattr(pkt, "payload") and pkt.payload:
                data = pkt.payload
            else:
                data = _build_minimal_ip_packet(
                    pkt.src_ip, pkt.dst_ip,
                    pkt.src_port, pkt.dst_port,
                    pkt.protocol, pkt.length,
                )
            # Parse timestamp
            try:
                from datetime import datetime as _dt
                dt = _dt.fromisoformat(pkt.timestamp.replace("Z", "+00:00"))
                ts = dt.timestamp()
            except Exception:
                ts = time.time()
            buf.write(_packet_record(ts, data))
            written += 1
        except Exception as e:
            log.debug("Skipping packet: %s", e)

    path.write_bytes(buf.getvalue())
    log.info("PCAP written: %s (%d packets, %d bytes)", path, written, path.stat().st_size)
    return path


def export_alert_pcap(alert_id: int, window_seconds: int = 60) -> Optional[Path]:
    """
    Export a pcap for the traffic around a specific alert (±window_seconds).
    Reconstructs packets from the traffic DB table.
    """
    from db import database as db

    alert = db.fetchone("SELECT * FROM alerts WHERE id=?", (alert_id,))
    if not alert:
        log.warning("Alert %d not found", alert_id)
        return None

    rows = db.fetchall(
        """SELECT * FROM traffic
           WHERE timestamp BETWEEN
             datetime(?, '-{} seconds') AND datetime(?, '+{} seconds')
           ORDER BY timestamp
           LIMIT 5000""".format(window_seconds, window_seconds),
        (alert["timestamp"], alert["timestamp"]),
    )

    if not rows:
        log.info("No traffic found for alert %d window", alert_id)
        return None

    ensure_pcap_dir()
    ts    = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    fname = f"alert_{alert_id}_{ts}.pcap"
    path  = PCAP_DIR / fname

    buf = io.BytesIO()
    buf.write(_global_header(PCAP_LINKTYPE_RAW))

    for row in rows:
        try:
            data = _build_minimal_ip_packet(
                row["src_ip"] or "0.0.0.0",
                row["dst_ip"] or "0.0.0.0",
                row["src_port"] or 0,
                row["dst_port"] or 0,
                row["protocol"] or "TCP",
                row["length"] or 60,
            )
            from datetime import datetime as _dt
            try:
                dt = _dt.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
                ts_f = dt.timestamp()
            except Exception:
                ts_f = time.time()
            buf.write(_packet_record(ts_f, data))
        except Exception as e:
            log.debug("Row skip: %s", e)

    path.write_bytes(buf.getvalue())
    log.info("Alert PCAP: %s (%d bytes)", path, path.stat().st_size)
    return path


def list_pcap_files() -> List[dict]:
    ensure_pcap_dir()
    files = []
    for f in sorted(PCAP_DIR.glob("*.pcap"), key=lambda x: x.stat().st_mtime, reverse=True):
        stat = f.stat()
        files.append({
            "name":     f.name,
            "path":     str(f),
            "size_kb":  round(stat.st_size / 1024, 1),
            "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M"),
        })
    return files


def delete_pcap(filename: str) -> bool:
    path = PCAP_DIR / filename
    if path.exists() and path.suffix == ".pcap":
        path.unlink()
        return True
    return False
