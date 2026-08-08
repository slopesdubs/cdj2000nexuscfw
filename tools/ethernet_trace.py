#!/usr/bin/env python3
"""Read-only PCAP/PCAPNG correlation scanner for CDJ waveform experiments."""

from __future__ import annotations

import argparse
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Sequence, Union


class CaptureError(ValueError):
    pass


@dataclass(frozen=True)
class Packet:
    index: int
    timestamp: Union[float, int]
    data: bytes


def iter_pcap(data: bytes) -> Iterable[Packet]:
    if len(data) < 24:
        raise CaptureError("truncated PCAP header")
    magic = data[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
        b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
        b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
        b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
    }
    if magic not in formats:
        raise CaptureError("unsupported PCAP magic")
    endian, scale = formats[magic]
    offset = 24
    index = 0
    while offset < len(data):
        if offset + 16 > len(data):
            raise CaptureError("truncated PCAP packet header")
        seconds, fraction, captured, _original = struct.unpack_from(
            endian + "IIII", data, offset
        )
        offset += 16
        if offset + captured > len(data):
            raise CaptureError("truncated PCAP packet")
        yield Packet(index, seconds + fraction / scale, data[offset : offset + captured])
        offset += captured
        index += 1


def iter_pcapng(data: bytes) -> Iterable[Packet]:
    offset = 0
    endian: Optional[str] = None
    index = 0
    while offset < len(data):
        if offset + 12 > len(data):
            raise CaptureError("truncated PCAPNG block")
        raw_type = data[offset : offset + 4]
        if raw_type == b"\x0a\x0d\x0d\x0a":
            bom = data[offset + 8 : offset + 12]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
            if endian is None:
                raise CaptureError("invalid PCAPNG byte-order magic")
        if endian is None:
            raise CaptureError("PCAPNG does not begin with a section header")
        block_type, block_length = struct.unpack_from(endian + "II", data, offset)
        if block_length < 12 or offset + block_length > len(data):
            raise CaptureError("invalid PCAPNG block length")
        if struct.unpack_from(endian + "I", data, offset + block_length - 4)[0] != block_length:
            raise CaptureError("mismatched PCAPNG trailing block length")
        if block_type == 6:
            if block_length < 32:
                raise CaptureError("truncated enhanced packet block")
            timestamp_high, timestamp_low, captured = struct.unpack_from(
                endian + "III", data, offset + 12
            )
            start = offset + 28
            if start + captured > offset + block_length - 4:
                raise CaptureError("truncated enhanced packet data")
            timestamp = (timestamp_high << 32) | timestamp_low
            yield Packet(index, timestamp, data[start : start + captured])
            index += 1
        elif block_type == 3:
            if block_length < 16:
                raise CaptureError("truncated simple packet block")
            original = struct.unpack_from(endian + "I", data, offset + 8)[0]
            captured = min(original, block_length - 16)
            yield Packet(index, index, data[offset + 12 : offset + 12 + captured])
            index += 1
        offset += block_length


def read_packets(path: Path) -> list[Packet]:
    data = path.read_bytes()
    if data.startswith(b"\x0a\x0d\x0d\x0a"):
        return list(iter_pcapng(data))
    return list(iter_pcap(data))


def pwv3_payload(path: Path) -> tuple[int, int, bytes]:
    data = path.read_bytes()
    offset = data.find(b"PWV3")
    if offset < 0 or offset + 24 > len(data):
        raise CaptureError("PWV3 is absent or truncated in the ANLZ sample")
    header, length, entry_size, count = struct.unpack_from(">IIII", data, offset + 4)
    if header < 24 or length < header or offset + length > len(data):
        raise CaptureError("invalid PWV3 lengths")
    payload = data[offset + header : offset + length]
    if entry_size * count != len(payload):
        raise CaptureError("PWV3 size product does not match its payload")
    return entry_size, count, payload


def scan_capture(path: Path, anlz_path: Optional[Path] = None) -> dict:
    packets = read_packets(path)
    needles: dict[str, bytes] = {
        "PMAI": b"PMAI",
        "PWV3": b"PWV3",
        "PWV4": b"PWV4",
        "PWV5": b"PWV5",
    }
    sample = None
    if anlz_path is not None:
        entry_size, count, payload = pwv3_payload(anlz_path)
        sample = {"entry_size": entry_size, "entry_count": count, "payload_length": len(payload)}
        for width in (16, 32, 64):
            if len(payload) >= width:
                needles[f"PWV3_payload_prefix_{width}"] = payload[:width]
        for label, value in (("entry_count", count), ("payload_length", len(payload)), ("tag_length", len(payload) + 24)):
            needles[f"{label}_be32"] = value.to_bytes(4, "big")
            needles[f"{label}_le32"] = value.to_bytes(4, "little")

    hits = []
    for packet in packets:
        for name, needle in needles.items():
            cursor = 0
            while True:
                found = packet.data.find(needle, cursor)
                if found < 0:
                    break
                hits.append(
                    {
                        "packet": packet.index,
                        "timestamp": packet.timestamp,
                        "needle": name,
                        "offset": found,
                    }
                )
                cursor = found + 1
    return {
        "capture": str(path.resolve()),
        "packets": len(packets),
        "bytes": sum(len(packet.data) for packet in packets),
        "anlz": sample,
        "hits": hits,
    }


def compare_captures(captures: Sequence[dict]) -> dict:
    """Summarize which needles repeat across every supplied capture."""

    hit_sets = [set(hit["needle"] for hit in capture["hits"]) for capture in captures]
    repeated = sorted(set.intersection(*hit_sets)) if hit_sets else []
    return {
        "capture_count": len(captures),
        "repeatability_test_possible": len(captures) >= 2,
        "needles_seen_in_every_capture": repeated,
        "hit_counts": {
            Path(capture["capture"]).name: len(capture["hits"]) for capture in captures
        },
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="scan CDJ Ethernet captures for ANLZ/PWV3 evidence")
    parser.add_argument("captures", nargs="+", type=Path)
    parser.add_argument("--anlz", type=Path)
    parser.add_argument("--output", "-o", type=Path)
    args = parser.parse_args(argv)
    try:
        captures = [scan_capture(path, args.anlz) for path in args.captures]
        result = {"captures": captures, "comparison": compare_captures(captures)}
    except (OSError, CaptureError) as exc:
        print(f"error: {exc}")
        return 2
    rendered = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(f"wrote capture scan to {args.output}")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
