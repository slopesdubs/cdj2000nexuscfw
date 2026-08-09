"""Reproducible stock-v1.44 Blackfin GUI detailed-waveform receiver trace."""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Sequence, Tuple

from upd_container import UpdError, parse_upd


STOCK_GUI_SHA256 = "94a6434727cb545195f58df69ffc010bb95ab3152af7edfd72e44c3d1f906bd2"
CODE_BASE = 0x00C60000
CODE_LIMIT = 0x00D50000
ZEROFILL = 0x0001
FINAL = 0x8000
PALETTE_ADDRESS = 0x00CD3928
RECORD_ARENA_BASE = 0x01011940
RECORD_ARENA_CLEAR_BYTES = 0x00A4CDD8
RECORD_ARENA_END = RECORD_ARENA_BASE + RECORD_ARENA_CLEAR_BYTES
RECORD_STRIDE = 12
CANONICAL_COLUMNS = 29_804
EXPECTED_RGB555_PALETTE = (
    0x0993,
    0x0A17,
    0x065F,
    0x0AFD,
    0x3F1C,
    0x4B1F,
    0x4B1F,
    0x6BBF,
)


class GuiTraceError(ValueError):
    """Raised when the GUI baseline or Blackfin disassembly is not trustworthy."""


@dataclass(frozen=True)
class LdrBlock:
    address: int
    count: int
    flags: int
    data: bytes


FOCUSED_RANGES: Sequence[Tuple[str, int, int]] = (
    ("sport1-dma3", 0x00D0C548, 0x00D0C66C),
    ("crc16-xmodem", 0x00D0CF1A, 0x00D0CFC6),
    ("receive-dispatch", 0x00D10778, 0x00D10928),
    ("detail-command-20", 0x00D0FA64, 0x00D0FE00),
    ("completion-event", 0x00D0F358, 0x00D0F540),
    ("column-consumer", 0x00D2F51C, 0x00D2F60E),
    ("record-arena-init", 0x00D2C0DE, 0x00D2C118),
    ("byte-fill", 0x00D4837C, 0x00D483DA),
    ("rgb555-packer", 0x00D2C052, 0x00D2C06A),
    ("column-renderer", 0x00D2E17C, 0x00D2E34E),
    ("waveform-surface", 0x00D2F0BE, 0x00D2F51C),
)


def load_gui_segment(path: Path) -> bytes:
    """Read either an extracted GUI.segment or a four-segment update."""

    data = path.read_bytes()
    if path.suffix.lower() == ".upd":
        try:
            return parse_upd(data).segments["GUI"]
        except (UpdError, KeyError) as exc:
            raise GuiTraceError(f"cannot extract GUI segment from {path}: {exc}") from exc
    return data


def parse_ldr_blocks(gui: bytes) -> List[LdrBlock]:
    """Parse the BF53x LDR stream after its 32-byte ASCII segment header."""

    position = 0x20
    blocks: List[LdrBlock] = []
    while position + 10 <= len(gui):
        address, count, flags = struct.unpack_from("<IIH", gui, position)
        position += 10
        if count > 0x400000:
            raise GuiTraceError(f"implausible LDR block size 0x{count:X}")
        if flags & ZEROFILL:
            body = b"\0" * count
        else:
            end = position + count
            if end > len(gui):
                raise GuiTraceError("truncated LDR block body")
            body = gui[position:end]
            position = end
        blocks.append(LdrBlock(address, count, flags, body))
        if flags & FINAL:
            return blocks
        if len(blocks) > 200_000:
            raise GuiTraceError("LDR block limit exceeded")
    raise GuiTraceError("LDR stream has no FINAL block")


def flatten_code(blocks: Sequence[LdrBlock]) -> bytes:
    """Materialize only the Blackfin code window, preserving load order."""

    image = bytearray(CODE_LIMIT - CODE_BASE)
    for block in blocks:
        start = max(block.address, CODE_BASE)
        end = min(block.address + block.count, CODE_LIMIT)
        if start >= end:
            continue
        source = start - block.address
        image[start - CODE_BASE : end - CODE_BASE] = block.data[
            source : source + end - start
        ]
    return bytes(image)


def _run_objdump(
    objdump: Path, image_path: Path, start: int, stop: int
) -> str:
    command = [
        str(objdump),
        "-D",
        "-b",
        "binary",
        "-m",
        "bfin",
        f"--adjust-vma=0x{CODE_BASE:08X}",
        f"--start-address=0x{start:08X}",
        f"--stop-address=0x{stop:08X}",
        str(image_path),
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode:
        raise GuiTraceError(result.stderr.strip() or "Blackfin objdump failed")
    return result.stdout


def _validate_disassembly(disassembly: Dict[str, str]) -> None:
    checks = {
        "sport1-dma3": ("d0c548:", "d0c59a:", "P1=0xffc00cc4", "R0=0xa7"),
        "crc16-xmodem": ("d0cf1a:", "R3=0x1102100", "R0 = R0 >> 0x8"),
        "receive-dispatch": ("d108d2:", "R7=0x20", "CALL 0x0xd0fa64"),
        "detail-command-20": (
            "d0fa64:",
            "P1=0x1f00042",
            "P0=0x1a65168",
            "R1=0x1f0004e",
        ),
        "completion-event": ("R2=0x20", "d0f4f4:", "CALL 0x0xd2f51c"),
        "column-consumer": (
            "d2f51c:",
            "P2=0x1a65168",
            "R5=0xe0",
            "R6=0x1f",
            "P0=0x1011940",
        ),
        "record-arena-init": (
            "d2c0de:",
            "R2=0xa4cdd8",
            "R0=0x1011940",
            "CALL 0x0xd4837c",
        ),
        "byte-fill": (
            "d4837c:",
            "P0 = R0",
            "P2 = R2",
            "B[P0++] = R1",
        ),
        "rgb555-packer": (
            "d2c052:",
            "R0 >>= 0x3",
            "R0 <<= 0xa",
            "R1 <<= 0x5",
        ),
        "column-renderer": (
            "d2e230:",
            "CALL 0x0xd2e17c",
            "CALL 0x0xd2e1e8",
            "P0=0x1011940",
            "P2=0xcd3928",
            "W[P5 ++ P1] = R0.L",
        ),
        "waveform-surface": (
            "d2f0be:",
            "CALL 0x0xd2e230",
            "d2f418:",
            "R6=0x320",
            "BITSET (R0, 0x10)",
            "R0=0x5a0190",
            "R2=0x1000000",
        ),
    }
    missing = [
        f"{name}: {needle}"
        for name, needles in checks.items()
        for needle in needles
        if needle not in disassembly[name]
    ]
    if missing:
        raise GuiTraceError("disassembly validation failed: " + "; ".join(missing))


def build_gui_receiver_trace(gui_path: Path, objdump_path: Path) -> Tuple[dict, Dict[str, str]]:
    gui = load_gui_segment(gui_path)
    digest = hashlib.sha256(gui).hexdigest()
    if digest != STOCK_GUI_SHA256:
        raise GuiTraceError(
            "GUI SHA-256 does not match the fixed stock-v1.44 baseline: " + digest
        )
    if not objdump_path.is_file():
        raise GuiTraceError(f"Blackfin objdump is missing: {objdump_path}")

    version = subprocess.run(
        [str(objdump_path), "--version"], check=False, capture_output=True, text=True
    )
    if version.returncode or "GNU objdump" not in version.stdout:
        raise GuiTraceError("objdump is not a working GNU objdump")

    blocks = parse_ldr_blocks(gui)
    image = flatten_code(blocks)
    with tempfile.TemporaryDirectory(prefix="cdj-gui-trace-") as directory:
        temporary_image = Path(directory) / "gui-flat.bin"
        temporary_image.write_bytes(image)
        focused = {
            name: _run_objdump(objdump_path, temporary_image, start, stop)
            for name, start, stop in FOCUSED_RANGES
        }
    _validate_disassembly(focused)
    palette = tuple(
        struct.unpack_from("<H", image, PALETTE_ADDRESS - CODE_BASE + index * 4)[0]
        for index in range(8)
    )
    palette_padding = tuple(
        struct.unpack_from("<H", image, PALETTE_ADDRESS - CODE_BASE + index * 4 + 2)[0]
        for index in range(8)
    )
    if palette != EXPECTED_RGB555_PALETTE or any(palette_padding):
        raise GuiTraceError(
            "stock palette validation failed: "
            + ", ".join(f"0x{value:04X}" for value in palette)
        )

    trace = {
        "schema": 1,
        "baseline": {
            "path": str(gui_path.resolve()),
            "sha256": digest,
            "ldr_blocks": len(blocks),
            "nonzero_blocks": sum(not (block.flags & ZEROFILL) for block in blocks),
            "objdump": version.stdout.splitlines()[0],
            "architecture": "Analog Devices Blackfin BF531, little-endian",
        },
        "transport": {
            "sport1_init": "0x00D0C548",
            "dma3_receive_setup": "0x00D0C59A",
            "dma3_start_address_register": "0xFFC00CC4",
            "dma3_word_count_register": "0xFFC00CD0",
            "dma3_modify": 2,
            "initial_header_address": "0x01F00000",
            "initial_header_words": 32,
            "frame_address": "0x01F00040",
            "frame_words": 448,
            "crc_input_bytes": 894,
            "crc_word_offset": 894,
        },
        "receiver": {
            "dispatch_read": "0x00D108D2 reads word at 0x01F00040",
            "message_word": 32,
            "handler": "0x00D0FA64",
            "first_frame": {
                "sequence_u32": "+2",
                "total_payload_u32": "+6",
                "opaque_word_10": "+10",
                "opaque_word_12": "+12",
                "source": "+14",
                "copy_bytes": 880,
            },
            "extension_frame": {
                "sequence_u32": "+2",
                "source": "+6",
                "copy_bytes": 888,
            },
            "reassembly_buffer": "0x01A65168",
            "write_offset_state": "0x006D4140",
            "total_bytes_state": "0x006D413C",
            "expected_sequence_state": "0x006D414A",
        },
        "consumer": {
            "completion_event": 32,
            "event_dispatch_compare": "0x00D0F36C",
            "event_handler": "0x00D0F4F4",
            "first_consumer": "0x00D2F51C",
            "source_buffer": "0x01A65168",
            "destination_base": f"0x{RECORD_ARENA_BASE:08X}",
            "record_stride": RECORD_STRIDE,
            "height": "raw & 0x1F",
            "legacy_color_code": "(raw & 0xE0) >> 5",
            "packed_word": "legacy_color_code << 8 | height",
            "record_offset_2": 0,
            "limit": (
                "The live conversion count is clamped through runtime state before "
                "the byte loop; the clamp bounds are not statically initialized."
            ),
            "record_arena": {
                "initializer": "0x00D2C0DE",
                "clear_routine": "0x00D4837C",
                "base": f"0x{RECORD_ARENA_BASE:08X}",
                "clear_bytes": RECORD_ARENA_CLEAR_BYTES,
                "end_exclusive": f"0x{RECORD_ARENA_END:08X}",
                "record_capacity": RECORD_ARENA_CLEAR_BYTES // RECORD_STRIDE,
                "canonical_columns": CANONICAL_COLUMNS,
                "canonical_record_bytes": CANONICAL_COLUMNS * RECORD_STRIDE,
                "canonical_end_exclusive": (
                    f"0x{RECORD_ARENA_BASE + CANONICAL_COLUMNS * RECORD_STRIDE:08X}"
                ),
                "evidence": (
                    "initializer passes base 0x01011940, zero fill byte, and "
                    "0x00A4CDD8-byte length to the verified byte-fill routine"
                ),
            },
        },
        "renderer": {
            "height_accessor": "0x00D2E17C",
            "legacy_color_accessor": "0x00D2E1E8",
            "column_renderer": "0x00D2E230",
            "renderer_call_sites": ["0x00D2F3B6", "0x00D2F3D8"],
            "palette_lookup": "0x00D2E2B8-0x00D2E2BE",
            "palette_address": f"0x{PALETTE_ADDRESS:08X}",
            "palette_entry_stride": 4,
            "palette_rgb555": [f"0x{value:04X}" for value in palette],
            "palette_padding_words": list(palette_padding),
            "rgb_packer": "0x00D2C052",
            "rgb_packer_formula": (
                "((red >> 3) << 10) | ((green >> 3) << 5) | (blue >> 3)"
            ),
            "pixel_format": "RGB555 stored as a little-endian 16-bit word",
            "surface_setup": "0x00D2F418",
            "surface_address": "0x01000000",
            "surface_dimensions": {"width": 400, "height": 90},
            "surface_row_bytes": 800,
            "surface_bytes": 72000,
            "waveform_baseline_address": "0x01008980",
            "vertical_row_step": -800,
            "maximum_height_pixels": 31,
            "registration": "0x00D2F4F8 calls 0x00D02600",
            "activation": "0x00D2F502 calls 0x00D02A48",
        },
        "boundary": {
            "proven": (
                "MAIN command-32 frame bytes -> SPORT1/DMA3 -> CRC gate -> command "
                "dispatch -> reassembly -> completion event -> legacy PWV3 columns "
                "-> palette lookup -> RGB555 waveform-layer pixels"
            ),
            "unresolved": (
                "Only the generic graphics compositor edge from the registered "
                "0x01000000 layer surface to DMA0 scanout at 0x00659B88 remains; "
                "the waveform colour-rendering boundary itself is proven."
            ),
        },
    }
    return trace, focused


def _markdown(trace: dict) -> str:
    b = trace["baseline"]
    t = trace["transport"]
    r = trace["receiver"]
    c = trace["consumer"]
    arena = c["record_arena"]
    renderer = trace["renderer"]
    return "\n".join(
        [
            "# Stock v1.44 GUI detailed-waveform receiver trace",
            "",
            f"Baseline `{b['sha256']}`, decoded with `{b['objdump']}`.",
            "",
            "## Proven path",
            "",
            f"- SPORT1 init `{t['sport1_init']}`; DMA3 RX setup `{t['dma3_receive_setup']}`.",
            f"- DMA first receives {t['initial_header_words']} words at `{t['initial_header_address']}`, then the frame at `{t['frame_address']}`.",
            f"- Word 0 is dispatched as command `{r['message_word']}` to `{r['handler']}`.",
            f"- First/continuation data starts at {r['first_frame']['source']} / {r['extension_frame']['source']} and copies {r['first_frame']['copy_bytes']} / {r['extension_frame']['copy_bytes']} bytes.",
            f"- Reassembly lands at `{r['reassembly_buffer']}`.",
            f"- Completion event `{c['completion_event']}` reaches `{c['first_consumer']}`.",
            f"- Each PWV3 byte becomes `height = {c['height']}` and `legacy_colour = {c['legacy_color_code']}` in a {c['record_stride']}-byte record at `{c['destination_base']}`.",
            f"- Stock initializer `{arena['initializer']}` clears {arena['clear_bytes']:,} bytes from `{arena['base']}` through `{arena['end_exclusive']}` using `{arena['clear_routine']}`, proving capacity for {arena['record_capacity']:,} records.",
            f"- The canonical {arena['canonical_columns']:,}-column waveform occupies only {arena['canonical_record_bytes']:,} bytes and ends at `{arena['canonical_end_exclusive']}`.",
            f"- `{renderer['column_renderer']}` reads those fields and indexes the eight-entry palette at `{renderer['palette_address']}`.",
            f"- The selected {renderer['pixel_format']} is written into the {renderer['surface_dimensions']['width']}×{renderer['surface_dimensions']['height']} layer at `{renderer['surface_address']}` with a {renderer['surface_row_bytes']}-byte row stride.",
            f"- The vertical waveform baseline is `{renderer['waveform_baseline_address']}`; columns extend upward by at most {renderer['maximum_height_pixels']} pixels.",
            "",
            "## Remaining generic compositor edge",
            "",
            trace["boundary"]["unresolved"],
            "",
        ]
    )


def write_gui_receiver_trace(
    trace: dict, disassemblies: Dict[str, str], output_directory: Path
) -> None:
    output_directory.mkdir(parents=True, exist_ok=True)
    (output_directory / "gui-receiver-trace.json").write_text(
        json.dumps(trace, indent=2) + "\n", encoding="utf-8"
    )
    (output_directory / "gui-receiver-trace.md").write_text(
        _markdown(trace), encoding="utf-8"
    )
    for name, text in disassemblies.items():
        (output_directory / f"{name}.dis.txt").write_text(text, encoding="utf-8")
