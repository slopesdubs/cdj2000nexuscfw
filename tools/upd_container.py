"""Parsing and validation helpers for Pioneer CDJ-2000NXS update files."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Tuple

from lzss_codec import decompress
from srec_parse import parse_srec
from upd_build import crc_xmodem


SEGMENT_NAMES = ("GUI", "DRIV", "MAIN", "PANL")


class UpdError(ValueError):
    """Raised when an update container fails structural validation."""


@dataclass(frozen=True)
class UpdImage:
    header_size: int
    sizes: Mapping[str, int]
    segments: Mapping[str, bytes]


@dataclass(frozen=True)
class CrcResult:
    valid: bool
    calculated: int
    stored: int
    byte_order: str
    covered_bytes: int
    padding_bytes: int = 0


@dataclass(frozen=True)
class MainPayload:
    offset: int
    compressed_length: int
    stored_checksum: int
    calculated_checksum: int
    decompressed: bytes

    @property
    def checksum_valid(self) -> bool:
        return self.stored_checksum == self.calculated_checksum


def parse_upd(data: bytes) -> UpdImage:
    """Parse the four decimal length lines and return the four raw segments."""

    offset = 0
    lengths: List[int] = []
    for index in range(4):
        end = data.find(b"\r\n", offset, offset + 32)
        if end < 0:
            raise UpdError(f"missing CRLF after container length {index + 1}")
        raw = data[offset:end]
        if not raw or not raw.isdigit():
            raise UpdError(f"invalid container length {raw!r}")
        lengths.append(int(raw))
        offset = end + 2

    expected = offset + sum(lengths)
    if expected != len(data):
        raise UpdError(
            f"container lengths resolve to {expected} bytes, file has {len(data)}"
        )

    segments: Dict[str, bytes] = {}
    sizes = dict(zip(SEGMENT_NAMES, lengths))
    cursor = offset
    for name in SEGMENT_NAMES:
        length = sizes[name]
        segments[name] = data[cursor : cursor + length]
        cursor += length
    return UpdImage(offset, sizes, segments)


def parse_single_segment_upd(data: bytes, name: str = "MAIN") -> UpdImage:
    """Parse the inferred per-processor ``<length>\r\n<segment>`` container."""

    end = data.find(b"\r\n", 0, 32)
    if end < 0:
        raise UpdError("missing CRLF after single-segment container length")
    raw = data[:end]
    if not raw or not raw.isdigit():
        raise UpdError(f"invalid single-segment container length {raw!r}")
    header_size = end + 2
    declared = int(raw)
    segment = data[header_size:]
    if declared != len(segment):
        raise UpdError(
            f"single-segment length says {declared} bytes, found {len(segment)}"
        )
    header = segment_ascii_header(segment)
    if name not in header:
        raise UpdError(f"single-segment header {header!r} does not identify {name}")
    return UpdImage(header_size, {name: declared}, {name: segment})


def verify_segment_crc(name: str, segment: bytes) -> CrcResult:
    """Verify the known segment CRC rule.

    GUI stores CRC16-XMODEM big-endian and may have a two-byte field immediately
    before it. S-record segments store the CRC little-endian.
    """

    if len(segment) < 2:
        raise UpdError(f"{name} segment is too short for a CRC")

    if name == "GUI":
        stored = int.from_bytes(segment[-2:], "big")
        candidates: Iterable[Tuple[int, int]] = ((2, 0), (4, 2))
        first_calculated = crc_xmodem(segment[:-2])
        for cut, padding in candidates:
            if len(segment) < cut:
                continue
            calculated = crc_xmodem(segment[:-cut])
            if calculated == stored:
                return CrcResult(
                    True, calculated, stored, "big", len(segment) - cut, padding
                )
        return CrcResult(
            False, first_calculated, stored, "big", len(segment) - 2, 0
        )

    stored = int.from_bytes(segment[-2:], "little")
    calculated = crc_xmodem(segment[:-2])
    return CrcResult(
        calculated == stored, calculated, stored, "little", len(segment) - 2
    )


def srec_flat_image(
    segment: bytes, fill: int = 0xFF, max_size: int = 64 * 1024 * 1024
) -> Tuple[bytes, List[Tuple[str, int]]]:
    """Convert an S-record segment to a flat, zero-based memory image."""

    _, chunks, entries = parse_srec(segment, validate=True)
    highest = max(address + len(blob) for address, blob in chunks)
    if highest > max_size:
        raise UpdError(
            f"S-record image would require {highest} bytes; limit is {max_size}"
        )
    image = bytearray([fill]) * highest
    written = bytearray(highest)
    for address, blob in chunks:
        end = address + len(blob)
        if any(written[address:end]):
            raise UpdError(f"overlapping S-record data at 0x{address:X}")
        image[address:end] = blob
        written[address:end] = b"\x01" * len(blob)
    return bytes(image), entries


def find_main_payload(
    image: bytes, offsets: Iterable[int] = (0x40000, 0x50000)
) -> MainPayload:
    """Locate, checksum, and decompress the MAIN LZSS payload."""

    failures: List[str] = []
    for offset in offsets:
        if offset + 6 > len(image):
            continue
        compressed_length = struct.unpack_from("<I", image, offset)[0]
        end = offset + 4 + compressed_length
        if compressed_length == 0 or end + 2 > len(image):
            failures.append(f"0x{offset:X}: invalid compressed length {compressed_length}")
            continue
        stored = struct.unpack_from("<H", image, end)[0]
        calculated = sum(image[offset:end]) & 0xFFFF
        if stored != calculated:
            failures.append(
                f"0x{offset:X}: checksum 0x{stored:04X} != 0x{calculated:04X}"
            )
            continue
        payload = decompress(image, offset + 4, compressed_length)
        return MainPayload(offset, compressed_length, stored, calculated, payload)

    detail = "; ".join(failures) if failures else "candidate offsets outside image"
    raise UpdError(f"no checksum-valid MAIN payload found ({detail})")


def segment_ascii_header(segment: bytes) -> str:
    """Return the printable portion of the 32-byte Pioneer segment header."""

    return segment[:32].split(b"\x00", 1)[0].decode("ascii", errors="replace").rstrip()
