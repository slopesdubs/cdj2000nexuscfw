"""Offline emulator for the NXS detailed-waveform MAIN-to-GUI frames.

The stock v1.44 constructors at 0xA425BD60 and 0xA425C0CC use one reusable
896-byte buffer.  The first frame carries 880 bytes after a 14-byte header;
extension frames carry 888 bytes after a 6-byte header.  A CRC16-XMODEM over
the first 894 bytes is stored little-endian in the final two bytes.

This module emulates that boundary only.  It does not emulate the SH-4 CPU,
the physical SPORT/DMA link, or the Blackfin GUI renderer.
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence

from anlz_color import AnlzError, parse_anlz
from upd_build import crc_xmodem


FRAME_SIZE = 896
CRC_OFFSET = 0x37E
CRC_INPUT_SIZE = CRC_OFFSET
MESSAGE_WORD = 32
FIRST_HEADER_SIZE = 14
FIRST_PAYLOAD_CAPACITY = CRC_OFFSET - FIRST_HEADER_SIZE
EXTENSION_HEADER_SIZE = 6
EXTENSION_PAYLOAD_CAPACITY = CRC_OFFSET - EXTENSION_HEADER_SIZE


class WaveEmulatorError(ValueError):
    """Raised for an invalid waveform source or emulated frame stream."""


@dataclass(frozen=True)
class WaveformSource:
    tag: str
    entry_size: int
    entry_count: int
    unknown: int
    payload: bytes


@dataclass(frozen=True)
class FrameInfo:
    sequence: int
    total_payload_bytes: Optional[int]
    payload_offset: int
    payload_bytes: int
    stored_crc: int
    calculated_crc: int

    @property
    def crc_valid(self) -> bool:
        return self.stored_crc == self.calculated_crc


def extract_waveform_source(data: bytes, tag_kind: str = "PWV3") -> WaveformSource:
    """Extract a generic 24-byte-header waveform tag without transforming it."""

    requested = tag_kind.upper()
    try:
        anlz = parse_anlz(data)
    except AnlzError as exc:
        raise WaveEmulatorError(str(exc)) from exc
    matches = anlz.find(requested)
    if not matches:
        raise WaveEmulatorError(f"{requested} is absent from the ANLZ file")
    tag = matches[0]
    if tag.header_length < 24 or len(tag.raw) < 24:
        raise WaveEmulatorError(f"{requested} header is shorter than 24 bytes")
    entry_size, entry_count, unknown = struct.unpack_from(">III", tag.raw, 12)
    payload_size = entry_size * entry_count
    available = tag.tag_length - tag.header_length
    if payload_size > available:
        raise WaveEmulatorError(
            f"{requested} declares {payload_size} payload bytes, only {available} exist"
        )
    payload = tag.raw[tag.header_length : tag.header_length + payload_size]
    return WaveformSource(requested, entry_size, entry_count, unknown, payload)


def frame_crc(frame_prefix: bytes) -> int:
    """Return the trailer algorithm used by firmware routine 0xA4310FC0."""

    if len(frame_prefix) != CRC_INPUT_SIZE:
        raise WaveEmulatorError(
            f"CRC input must be {CRC_INPUT_SIZE} bytes, received {len(frame_prefix)}"
        )
    return crc_xmodem(frame_prefix)


def _finish_frame(buffer: bytearray) -> bytes:
    checksum = frame_crc(bytes(buffer[:CRC_OFFSET]))
    struct.pack_into("<H", buffer, CRC_OFFSET, checksum)
    return bytes(buffer)


def encode_detail_frames(
    payload: bytes,
    header_word_10: int = 0,
    header_word_12: int = 0,
) -> List[bytes]:
    """Encode raw waveform bytes exactly like the two stock chunk constructors.

    The two opaque first-frame words are exposed rather than assigned speculative
    semantics.  The reusable buffer is intentionally retained between extension
    frames, matching the firmware: unused bytes in the final frame retain bytes
    from the preceding frame and are ignored according to the total payload size.
    """

    if len(payload) > 0xFFFFFFFF:
        raise WaveEmulatorError("waveform payload exceeds the 32-bit frame length")
    for name, value in (
        ("header_word_10", header_word_10),
        ("header_word_12", header_word_12),
    ):
        if not 0 <= value <= 0xFFFF:
            raise WaveEmulatorError(f"{name} must fit in an unsigned 16-bit word")

    buffer = bytearray(FRAME_SIZE)
    sequence = 1
    struct.pack_into(
        "<HIIHH",
        buffer,
        0,
        MESSAGE_WORD,
        sequence,
        len(payload),
        header_word_10,
        header_word_12,
    )
    first_count = min(len(payload), FIRST_PAYLOAD_CAPACITY)
    buffer[FIRST_HEADER_SIZE : FIRST_HEADER_SIZE + first_count] = payload[:first_count]
    frames = [_finish_frame(buffer)]

    cursor = first_count
    while cursor < len(payload):
        sequence += 1
        struct.pack_into("<HI", buffer, 0, MESSAGE_WORD, sequence)
        count = min(len(payload) - cursor, EXTENSION_PAYLOAD_CAPACITY)
        buffer[
            EXTENSION_HEADER_SIZE : EXTENSION_HEADER_SIZE + count
        ] = payload[cursor : cursor + count]
        frames.append(_finish_frame(buffer))
        cursor += count
    return frames


def inspect_detail_frames(frames: Sequence[bytes]) -> List[FrameInfo]:
    """Validate frame size, type, order, count, and every CRC trailer."""

    if not frames:
        raise WaveEmulatorError("frame stream is empty")

    total_payload_bytes: Optional[int] = None
    remaining = 0
    information: List[FrameInfo] = []
    for index, frame in enumerate(frames, start=1):
        if len(frame) != FRAME_SIZE:
            raise WaveEmulatorError(
                f"frame {index} is {len(frame)} bytes, expected {FRAME_SIZE}"
            )
        message_word, sequence = struct.unpack_from("<HI", frame, 0)
        if message_word != MESSAGE_WORD:
            raise WaveEmulatorError(
                f"frame {index} has message word {message_word}, expected {MESSAGE_WORD}"
            )
        if sequence != index:
            raise WaveEmulatorError(
                f"frame {index} has sequence {sequence}, expected {index}"
            )

        stored_crc = struct.unpack_from("<H", frame, CRC_OFFSET)[0]
        calculated_crc = frame_crc(frame[:CRC_OFFSET])
        if stored_crc != calculated_crc:
            raise WaveEmulatorError(
                f"frame {index} CRC mismatch: stored 0x{stored_crc:04X}, "
                f"calculated 0x{calculated_crc:04X}"
            )

        if index == 1:
            total_payload_bytes = struct.unpack_from("<I", frame, 6)[0]
            payload_offset = FIRST_HEADER_SIZE
            payload_bytes = min(total_payload_bytes, FIRST_PAYLOAD_CAPACITY)
            remaining = total_payload_bytes - payload_bytes
        else:
            if remaining <= 0:
                raise WaveEmulatorError(f"frame {index} appears after payload completion")
            payload_offset = EXTENSION_HEADER_SIZE
            payload_bytes = min(remaining, EXTENSION_PAYLOAD_CAPACITY)
            remaining -= payload_bytes

        information.append(
            FrameInfo(
                sequence,
                total_payload_bytes if index == 1 else None,
                payload_offset,
                payload_bytes,
                stored_crc,
                calculated_crc,
            )
        )

    if remaining:
        raise WaveEmulatorError(
            f"frame stream ends with {remaining} waveform bytes still missing"
        )
    return information


def reassemble_detail_frames(frames: Sequence[bytes]) -> bytes:
    information = inspect_detail_frames(frames)
    return b"".join(
        frame[item.payload_offset : item.payload_offset + item.payload_bytes]
        for frame, item in zip(frames, information)
    )


def emulate_anlz_file(
    source_path: Path,
    output_directory: Path,
    tag_kind: str = "PWV3",
    header_word_10: int = 0,
    header_word_12: int = 0,
) -> dict:
    """Generate frames, a reassembled payload, and a JSON verification manifest."""

    source = extract_waveform_source(source_path.read_bytes(), tag_kind)
    frames = encode_detail_frames(source.payload, header_word_10, header_word_12)
    information = inspect_detail_frames(frames)
    reassembled = reassemble_detail_frames(frames)
    if reassembled != source.payload:
        raise WaveEmulatorError("internal error: reassembled waveform differs from source")

    output_directory.mkdir(parents=True, exist_ok=True)
    frame_entries = []
    for frame, item in zip(frames, information):
        name = f"frame-{item.sequence:04d}.bin"
        (output_directory / name).write_bytes(frame)
        frame_entries.append(
            {
                "file": name,
                "sequence": item.sequence,
                "payload_offset": item.payload_offset,
                "payload_bytes": item.payload_bytes,
                "crc": f"0x{item.stored_crc:04X}",
                "sha256": hashlib.sha256(frame).hexdigest(),
            }
        )

    (output_directory / "source-payload.bin").write_bytes(source.payload)
    (output_directory / "reassembled-payload.bin").write_bytes(reassembled)
    payload_digest = hashlib.sha256(source.payload).hexdigest()
    manifest = {
        "schema": 1,
        "emulator_scope": "stock NXS detailed-waveform MAIN-to-GUI frame boundary",
        "source": {
            "path": str(source_path.resolve()),
            "tag": source.tag,
            "entry_size": source.entry_size,
            "entry_count": source.entry_count,
            "unknown": f"0x{source.unknown:08X}",
            "payload_bytes": len(source.payload),
            "payload_sha256": payload_digest,
        },
        "protocol": {
            "message_word": MESSAGE_WORD,
            "frame_size": FRAME_SIZE,
            "crc": "CRC16-XMODEM over bytes 0..893; little-endian trailer",
            "first_payload_offset": FIRST_HEADER_SIZE,
            "first_payload_capacity": FIRST_PAYLOAD_CAPACITY,
            "extension_payload_offset": EXTENSION_HEADER_SIZE,
            "extension_payload_capacity": EXTENSION_PAYLOAD_CAPACITY,
            "opaque_header_word_10": header_word_10,
            "opaque_header_word_12": header_word_12,
            "compatibility": (
                "stock-v1.44 verified envelope"
                if source.tag == "PWV3"
                else "experimental: non-PWV3 bytes in the verified stock envelope"
            ),
        },
        "frames": frame_entries,
        "verification": {
            "all_crc_valid": all(item.crc_valid for item in information),
            "reassembled_payload_sha256": hashlib.sha256(reassembled).hexdigest(),
            "byte_identical_round_trip": reassembled == source.payload,
        },
    }
    (output_directory / "manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
    )
    return manifest
