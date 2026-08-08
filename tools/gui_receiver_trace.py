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
            "destination_base": "0x01011940",
            "record_stride": 12,
            "height": "raw & 0x1F",
            "legacy_color_code": "(raw & 0xE0) >> 5",
            "packed_word": "legacy_color_code << 8 | height",
            "record_offset_2": 0,
            "limit": (
                "The live conversion count is clamped through runtime state before "
                "the byte loop; the clamp bounds are not statically initialized."
            ),
        },
        "boundary": {
            "proven": (
                "MAIN command-32 frame bytes -> SPORT1/DMA3 -> CRC gate -> command "
                "dispatch -> reassembly -> completion event -> legacy PWV3 columns"
            ),
            "unresolved": (
                "The next indirect drawing call that turns the 12-byte column records "
                "into RGB565 framebuffer pixels."
            ),
        },
    }
    return trace, focused


def _markdown(trace: dict) -> str:
    b = trace["baseline"]
    t = trace["transport"]
    r = trace["receiver"]
    c = trace["consumer"]
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
            "",
            "## Remaining edge",
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
