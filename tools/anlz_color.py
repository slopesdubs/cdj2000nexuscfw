"""Dependency-free rekordbox ANLZ colour-waveform parser and PNG renderer.

PWV5's packed RGB/height fields are documented and decoded directly. PWV4's
six-byte preview columns contain fields whose exact visual interpretation is still
partly inferred; raw values are retained and the renderer follows the established
open-source interpretation described in ``docs/LAB.md``.
"""

from __future__ import annotations

import binascii
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence, Tuple


RGB = Tuple[int, int, int]


class AnlzError(ValueError):
    """Raised when an ANLZ file or waveform tag is structurally invalid."""


@dataclass(frozen=True)
class AnlzTag:
    kind: str
    offset: int
    header_length: int
    tag_length: int
    raw: bytes

    @property
    def content(self) -> bytes:
        return self.raw[12:]


@dataclass(frozen=True)
class AnlzFile:
    header_length: int
    file_length: int
    tags: Sequence[AnlzTag]

    def find(self, kind: str) -> List[AnlzTag]:
        return [tag for tag in self.tags if tag.kind == kind]


@dataclass(frozen=True)
class Pwv4Column:
    unknown: int
    luminance: int
    inverse_blue: int
    red: int
    green: int
    blue_height: int


@dataclass(frozen=True)
class Pwv3Column:
    raw: int
    height: int
    color: int


@dataclass(frozen=True)
class Pwv5Column:
    raw: int
    red: int
    green: int
    blue: int
    height: int


@dataclass(frozen=True)
class RenderColumn:
    height: int
    maximum: int
    color: RGB
    back_height: int = 0
    back_color: RGB = (0, 0, 0)


def parse_anlz(data: bytes) -> AnlzFile:
    """Parse the PMAI header and generic tag boundaries of an ANLZ file."""

    if len(data) < 28:
        raise AnlzError("file is too short for a PMAI header")
    kind, header_length, file_length, _, _, _, _ = struct.unpack_from(
        ">4s6I", data, 0
    )
    if kind != b"PMAI":
        raise AnlzError(f"expected PMAI header, found {kind!r}")
    if header_length < 28 or header_length > len(data):
        raise AnlzError(f"invalid PMAI header length {header_length}")
    if file_length > len(data):
        raise AnlzError(
            f"PMAI length says {file_length} bytes, input has only {len(data)}"
        )
    if file_length < header_length:
        raise AnlzError("PMAI file length is smaller than its header")

    tags: List[AnlzTag] = []
    offset = header_length
    while offset < file_length:
        if offset + 12 > file_length:
            raise AnlzError(f"truncated tag header at 0x{offset:X}")
        raw_kind, tag_header, tag_length = struct.unpack_from(">4sII", data, offset)
        try:
            tag_kind = raw_kind.decode("ascii")
        except UnicodeDecodeError as exc:
            raise AnlzError(f"non-ASCII tag at 0x{offset:X}") from exc
        if tag_header < 12 or tag_header > tag_length:
            raise AnlzError(
                f"{tag_kind} at 0x{offset:X} has invalid header length {tag_header}"
            )
        end = offset + tag_length
        if end > file_length:
            raise AnlzError(f"{tag_kind} at 0x{offset:X} extends past the file")
        tags.append(AnlzTag(tag_kind, offset, tag_header, tag_length, data[offset:end]))
        offset = end

    return AnlzFile(header_length, file_length, tags)


def parse_pwv4(tag: AnlzTag) -> Tuple[int, List[Pwv4Column]]:
    """Decode a six-byte-per-column colour preview tag."""

    if tag.kind != "PWV4":
        raise AnlzError(f"expected PWV4, received {tag.kind}")
    if tag.header_length < 24 or len(tag.content) < 12:
        raise AnlzError("PWV4 header is too short")
    entry_size, count, unknown = struct.unpack_from(">III", tag.content, 0)
    if entry_size != 6:
        raise AnlzError(f"PWV4 entry size is {entry_size}, expected 6")
    payload = tag.raw[tag.header_length :]
    expected = count * entry_size
    if len(payload) < expected:
        raise AnlzError(f"PWV4 needs {expected} entry bytes, found {len(payload)}")
    columns = [
        Pwv4Column(
            payload[i],
            payload[i + 1],
            payload[i + 2] & 0x7F,
            payload[i + 3] & 0x7F,
            payload[i + 4] & 0x7F,
            payload[i + 5] & 0x7F,
        )
        for i in range(0, expected, 6)
    ]
    return unknown, columns


def parse_pwv3(tag: AnlzTag) -> Tuple[int, List[Pwv3Column]]:
    """Decode PWV3's 3-bit intensity and 5-bit height entries."""

    if tag.kind != "PWV3":
        raise AnlzError(f"expected PWV3, received {tag.kind}")
    if tag.header_length < 24 or len(tag.content) < 12:
        raise AnlzError("PWV3 header is too short")
    entry_size, count, unknown = struct.unpack_from(">III", tag.content, 0)
    if entry_size != 1:
        raise AnlzError(f"PWV3 entry size is {entry_size}, expected 1")
    payload = tag.raw[tag.header_length :]
    if len(payload) < count:
        raise AnlzError(f"PWV3 needs {count} entry bytes, found {len(payload)}")
    return unknown, [
        Pwv3Column(value, value & 0x1F, value >> 5) for value in payload[:count]
    ]


def parse_pwv5(tag: AnlzTag) -> Tuple[int, List[Pwv5Column]]:
    """Decode PWV5's big-endian 3-bit RGB and 5-bit height entries."""

    if tag.kind != "PWV5":
        raise AnlzError(f"expected PWV5, received {tag.kind}")
    if tag.header_length < 24 or len(tag.content) < 12:
        raise AnlzError("PWV5 header is too short")
    entry_size, count, unknown = struct.unpack_from(">III", tag.content, 0)
    if entry_size != 2:
        raise AnlzError(f"PWV5 entry size is {entry_size}, expected 2")
    payload = tag.raw[tag.header_length :]
    expected = count * entry_size
    if len(payload) < expected:
        raise AnlzError(f"PWV5 needs {expected} entry bytes, found {len(payload)}")

    columns: List[Pwv5Column] = []
    for (value,) in struct.iter_unpack(">H", payload[:expected]):
        columns.append(
            Pwv5Column(
                value,
                (value >> 13) & 0x07,
                (value >> 10) & 0x07,
                (value >> 7) & 0x07,
                (value >> 2) & 0x1F,
            )
        )
    return unknown, columns


def _clamp(value: float) -> int:
    return max(0, min(255, round(value)))


def pwv4_render_columns(columns: Sequence[Pwv4Column]) -> List[RenderColumn]:
    """Map PWV4 fields to display columns using the current inferred model."""

    rendered: List[RenderColumn] = []
    for column in columns:
        boost = column.luminance / 127 if column.luminance else 0
        base = tuple(
            _clamp(component * boost * 2)
            for component in (column.red, column.green, column.blue_height)
        )
        front = tuple(_clamp(component + 64) for component in base)
        rendered.append(
            RenderColumn(
                column.blue_height,
                127,
                front,
                max(column.inverse_blue, column.red, column.green),
                base,
            )
        )
    return rendered


def pwv5_render_columns(columns: Sequence[Pwv5Column]) -> List[RenderColumn]:
    return [
        RenderColumn(
            column.height,
            31,
            tuple(
                component * 255 // 7
                for component in (column.red, column.green, column.blue)
            ),
        )
        for column in columns
    ]


def choose_color_tag(anlz: AnlzFile, requested: str = "auto") -> AnlzTag:
    requested = requested.upper()
    priorities = ("PWV4", "PWV5") if requested == "AUTO" else (requested,)
    for kind in priorities:
        matches = anlz.find(kind)
        if matches:
            return matches[0]
    raise AnlzError(f"no requested colour tag found ({', '.join(priorities)})")


def _resample(columns: Sequence[RenderColumn], width: int) -> List[RenderColumn]:
    if not columns:
        raise AnlzError("waveform contains no columns")
    output: List[RenderColumn] = []
    count = len(columns)
    for x in range(width):
        start = x * count // width
        end = max(start + 1, (x + 1) * count // width)
        group = columns[start:min(end, count)]
        output.append(
            max(
                group,
                key=lambda item: max(
                    item.height / max(1, item.maximum),
                    item.back_height / max(1, item.maximum),
                ),
            )
        )
    return output


def render_waveform(
    columns: Sequence[RenderColumn], width: int = 480, height: int = 128
) -> bytes:
    """Render symmetric waveform columns into packed RGB pixels."""

    if width <= 0 or height < 8:
        raise ValueError("width must be positive and height must be at least 8")
    sampled = _resample(columns, width)
    background = (5, 12, 22)
    grid = (18, 31, 47)
    pixels = bytearray(background * (width * height))

    def set_pixel(x: int, y: int, color: RGB) -> None:
        if 0 <= x < width and 0 <= y < height:
            index = (y * width + x) * 3
            pixels[index : index + 3] = bytes(color)

    for fraction in (1, 2, 3):
        x = width * fraction // 4
        for y in range(height):
            set_pixel(x, y, grid)
    middle = height // 2
    for x, column in enumerate(sampled):
        layers = (
            (column.back_height, column.back_color),
            (column.height, column.color),
        )
        for raw_height, color in layers:
            if raw_height <= 0:
                continue
            half = max(1, round((height // 2 - 2) * raw_height / column.maximum))
            for y in range(middle - half, middle + half + 1):
                set_pixel(x, y, color)
    return bytes(pixels)


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    checksum = binascii.crc32(kind + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", checksum)


def png_bytes(width: int, height: int, pixels: bytes) -> bytes:
    if len(pixels) != width * height * 3:
        raise ValueError("pixel buffer length does not match width and height")
    scanlines = b"".join(
        b"\x00" + pixels[y * width * 3 : (y + 1) * width * 3]
        for y in range(height)
    )
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _png_chunk(b"IDAT", zlib.compress(scanlines, 9))
        + _png_chunk(b"IEND", b"")
    )


def render_anlz_file(
    input_path: Path,
    output_path: Path,
    requested_tag: str = "auto",
    width: int = 480,
    height: int = 128,
) -> str:
    anlz = parse_anlz(input_path.read_bytes())
    tag = choose_color_tag(anlz, requested_tag)
    if tag.kind == "PWV4":
        _, decoded = parse_pwv4(tag)
        columns = pwv4_render_columns(decoded)
    else:
        _, decoded = parse_pwv5(tag)
        columns = pwv5_render_columns(decoded)
    pixels = render_waveform(columns, width, height)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(png_bytes(width, height, pixels))
    return tag.kind
