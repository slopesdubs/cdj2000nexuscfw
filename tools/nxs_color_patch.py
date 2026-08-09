"""Build and verify an offline experimental PWV5 colour-waveform update.

This module is deliberately hash-gated to the stock CDJ-2000NXS v1.44 MAIN and
GUI images.  It never flashes a device.  Generated firmware remains ignored and
must not be redistributed.
"""

from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import List, Sequence, Tuple

from gui_receiver_trace import (
    FINAL,
    RECORD_ARENA_BASE,
    RECORD_ARENA_CLEAR_BYTES,
    RECORD_ARENA_END,
    RECORD_STRIDE,
    STOCK_GUI_SHA256,
    ZEROFILL,
)
from lzss_codec import compress
from sh4_trace import STOCK_V144_SHA256
from srec_parse import parse_srec
from upd_build import build_srec_segment, build_upd, crc_xmodem
from upd_container import (
    SEGMENT_NAMES,
    find_main_payload,
    parse_upd,
    srec_flat_image,
    verify_segment_crc,
)


MAIN_TAG_OFFSETS = (0x000ACE60, 0x000ACEE4, 0x000ACF4C)
MAIN_INTERNAL_VERSION_OFFSET = 0x00000740
# 0xA425B9EA normally loads descriptor +0 (entry count). PWV5 needs the
# already-validated descriptor +8 value (entry_size * entry_count) so MAIN
# transports both bytes belonging to every colour-waveform column.
MAIN_TRANSPORT_LENGTH_OFFSET = 0x0025B9EA
MAIN_TRANSPORT_LENGTH_STOCK = bytes.fromhex("2266")
MAIN_TRANSPORT_LENGTH_PWV5 = bytes.fromhex("2256")
GUI_INJECTION_ADDRESS = 0x00D4A000
GUI_CONSUMER_CALL_ADDRESS = 0x00D0F538
GUI_FIRST_COPY_CALL_ADDRESS = 0x00D0FC22
GUI_FIRST_BUFFER_ADDRESS = 0x00D0FC08
GUI_EXTENSION_BUFFER_ADDRESS = 0x00D0FD20
GUI_RENDERER_BUFFER_ADDRESS = 0x00D2E2A6
GUI_RENDERER_LOAD_ADDRESS = 0x00D2E2B8
CANONICAL_MAX_COLUMNS = 29_804


class ColorPatchError(ValueError):
    """Raised when a baseline or proposed patch fails a safety invariant."""


@dataclass(frozen=True)
class LocatedLdrBlock:
    header_offset: int
    data_offset: int
    address: int
    count: int
    flags: int


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def locate_ldr_blocks(gui: bytes) -> List[LocatedLdrBlock]:
    """Return LDR blocks with file offsets, including the FINAL block."""

    position = 0x20
    blocks: List[LocatedLdrBlock] = []
    while position + 10 <= len(gui):
        header_offset = position
        address, count, flags = struct.unpack_from("<IIH", gui, position)
        position += 10
        data_offset = position
        if count > 0x400000:
            raise ColorPatchError(f"implausible GUI LDR block size 0x{count:X}")
        if not (flags & ZEROFILL):
            position += count
            if position > len(gui):
                raise ColorPatchError("truncated GUI LDR block")
        blocks.append(LocatedLdrBlock(header_offset, data_offset, address, count, flags))
        if flags & FINAL:
            return blocks
    raise ColorPatchError("GUI LDR stream has no FINAL block")


def _patch_loaded_bytes(
    gui: bytearray, blocks: Sequence[LocatedLdrBlock], address: int, expected: bytes, replacement: bytes
) -> None:
    if len(expected) != len(replacement):
        raise ColorPatchError("in-place GUI patch changes instruction span")
    for block in blocks:
        if block.flags & ZEROFILL:
            continue
        if block.address <= address and address + len(expected) <= block.address + block.count:
            offset = block.data_offset + address - block.address
            actual = bytes(gui[offset : offset + len(expected)])
            if actual != expected:
                raise ColorPatchError(
                    f"GUI bytes at 0x{address:08X} are {actual.hex()}, expected {expected.hex()}"
                )
            gui[offset : offset + len(replacement)] = replacement
            return
    raise ColorPatchError(f"GUI address 0x{address:08X} is not in a loaded data block")


def _validate_injection_range(
    blocks: Sequence[LocatedLdrBlock], address: int, size: int
) -> None:
    final_index = next(index for index, block in enumerate(blocks) if block.flags & FINAL)
    zeroed = False
    for block in blocks[:final_index]:
        overlaps = block.address < address + size and address < block.address + block.count
        if not overlaps:
            continue
        if block.address <= address and address + size <= block.address + block.count:
            zeroed = bool(block.flags & ZEROFILL)
        elif not (block.flags & ZEROFILL):
            raise ColorPatchError("GUI injection range overlaps loaded stock data")
    if not zeroed:
        raise ColorPatchError("GUI injection range is not covered by stock zero-fill")


def patch_gui_segment(
    gui: bytes,
    consumer_blob: bytes,
    call_hook: bytes,
    first_copy_hook: bytes,
    renderer_load: bytes,
    gui_version: bytes = b"1.201",
) -> bytes:
    """Patch the stock GUI LDR segment and append one injected code block."""

    if _sha256(gui) != STOCK_GUI_SHA256:
        raise ColorPatchError("GUI segment does not match stock NXS v1.44")
    if not consumer_blob or len(consumer_blob) > 0x400:
        raise ColorPatchError("GUI consumer blob must contain at most 1 KiB")
    if len(call_hook) != 4 or len(first_copy_hook) != 4 or len(renderer_load) != 8:
        raise ColorPatchError("unexpected assembled hook size")
    if len(gui_version) != 5 or not gui_version.startswith(b"1."):
        raise ColorPatchError("GUI version must be five ASCII bytes such as 1.201")

    blocks = locate_ldr_blocks(gui)
    _validate_injection_range(blocks, GUI_INJECTION_ADDRESS, len(consumer_blob))
    patched = bytearray(gui)
    _patch_loaded_bytes(
        patched,
        blocks,
        GUI_CONSUMER_CALL_ADDRESS,
        bytes.fromhex("00e3f2ff"),
        call_hook,
    )
    _patch_loaded_bytes(
        patched,
        blocks,
        GUI_FIRST_COPY_CALL_ADDRESS,
        bytes.fromhex("01e3b9cb"),
        first_copy_hook,
    )
    for address in (GUI_FIRST_BUFFER_ADDRESS, GUI_EXTENSION_BUFFER_ADDRESS):
        _patch_loaded_bytes(
            patched,
            blocks,
            address,
            bytes.fromhex("08e1685148e1a601"),
            bytes.fromhex("08e1401948e10101"),
        )
    _patch_loaded_bytes(
        patched,
        blocks,
        GUI_RENDERER_BUFFER_ADDRESS,
        bytes.fromhex("0ae128394ae1cd00"),
        bytes.fromhex("0ae144194ae10101"),
    )
    _patch_loaded_bytes(
        patched,
        blocks,
        GUI_RENDERER_LOAD_ADDRESS,
        bytes.fromhex("f1ae4a5e00000982"),
        renderer_load,
    )

    final_offset = blocks[-1].header_offset
    injected_block = struct.pack(
        "<IIH", GUI_INJECTION_ADDRESS, len(consumer_blob), 0
    ) + consumer_blob
    patched[final_offset:final_offset] = injected_block

    old_version = b"1.200"
    if patched.count(old_version) != 2:
        raise ColorPatchError("expected exactly two GUI 1.200 version fields")
    patched = bytearray(bytes(patched).replace(old_version, gui_version))
    patched[-2:] = crc_xmodem(bytes(patched[:-4])).to_bytes(2, "big")
    if not verify_segment_crc("GUI", bytes(patched)).valid:
        raise ColorPatchError("rebuilt GUI CRC verification failed")
    if len(locate_ldr_blocks(bytes(patched))) != len(blocks) + 1:
        raise ColorPatchError("injected GUI LDR block was not preserved")
    return bytes(patched)


def patch_main_decompressed(
    image: bytes, main_version: bytes = b"1.46", strict_hash: bool = True
) -> bytes:
    """Accept PWV5 and transport its payload byte count from a decompressed MAIN."""

    if strict_hash and _sha256(image) != STOCK_V144_SHA256:
        raise ColorPatchError("decompressed MAIN does not match stock NXS v1.44")
    if len(main_version) != 4 or not main_version.startswith(b"1."):
        raise ColorPatchError("MAIN version must be four ASCII bytes such as 1.46")
    patched = bytearray(image)
    for offset in MAIN_TAG_OFFSETS:
        if patched[offset : offset + 4] != b"PWV3":
            raise ColorPatchError(
                f"stock PWV3 tag literal is absent at 0x{0xA4000000 + offset:08X}"
            )
    actual_length_load = bytes(
        patched[MAIN_TRANSPORT_LENGTH_OFFSET : MAIN_TRANSPORT_LENGTH_OFFSET + 2]
    )
    if actual_length_load != MAIN_TRANSPORT_LENGTH_STOCK:
        raise ColorPatchError(
            "stock detailed-waveform entry-count load is absent at 0xA425B9EA"
        )
    if patched[MAIN_INTERNAL_VERSION_OFFSET : MAIN_INTERNAL_VERSION_OFFSET + 4] != b"1.44":
        raise ColorPatchError("stock internal MAIN version is absent at 0xA4000740")
    for offset in MAIN_TAG_OFFSETS:
        patched[offset : offset + 4] = b"PWV5"
    patched[
        MAIN_TRANSPORT_LENGTH_OFFSET : MAIN_TRANSPORT_LENGTH_OFFSET + 2
    ] = MAIN_TRANSPORT_LENGTH_PWV5
    patched[
        MAIN_INTERNAL_VERSION_OFFSET : MAIN_INTERNAL_VERSION_OFFSET + 4
    ] = main_version
    return bytes(patched)


def rebuild_main_segment(
    segment: bytes, main_version: bytes = b"1.46"
) -> Tuple[bytes, dict]:
    """Patch, recompress, and rebuild the stock MAIN S-record segment."""

    s0_payload, chunks, entries = parse_srec(segment, validate=True)
    if len(entries) != 1 or entries[0][0] != "7":
        raise ColorPatchError("MAIN segment does not have one S7 entry")
    flat, _ = srec_flat_image(segment)
    payload = find_main_payload(flat)
    patched_decompressed = patch_main_decompressed(payload.decompressed, main_version)
    # The default fast search is ~83 bytes larger than the stock stream. A 128-entry
    # candidate window remains deterministic and produces a smaller in-place image.
    compressed = compress(patched_decompressed, max_candidates=128)
    end = payload.offset + 4 + len(compressed)
    if end + 2 > len(flat):
        raise ColorPatchError("patched MAIN compressed stream no longer fits")

    patched_flat = bytearray(flat)
    patched_flat[payload.offset:] = b"\xFF" * (len(flat) - payload.offset)
    struct.pack_into("<I", patched_flat, payload.offset, len(compressed))
    patched_flat[payload.offset + 4 : end] = compressed
    checksum = sum(patched_flat[payload.offset:end]) & 0xFFFF
    struct.pack_into("<H", patched_flat, end, checksum)

    rebuilt_chunks = [
        (address, bytes(patched_flat[address : address + len(body)]))
        for address, body in chunks
    ]
    ascii_header = bytearray(segment[:32])
    if ascii_header.count(b"Ver1.44") != 1:
        raise ColorPatchError("stock MAIN segment version header is absent")
    ascii_header = ascii_header.replace(b"Ver1.44", b"Ver" + main_version)
    rebuilt = build_srec_segment(
        bytes(ascii_header), s0_payload, rebuilt_chunks, entries[0][1]
    )
    if not verify_segment_crc("MAIN", rebuilt).valid:
        raise ColorPatchError("rebuilt MAIN CRC verification failed")
    verified = find_main_payload(srec_flat_image(rebuilt)[0])
    if any(
        verified.decompressed[offset : offset + 4] != b"PWV5"
        for offset in MAIN_TAG_OFFSETS
    ):
        raise ColorPatchError("rebuilt MAIN does not contain all three PWV5 tag patches")
    if (
        verified.decompressed[
            MAIN_TRANSPORT_LENGTH_OFFSET : MAIN_TRANSPORT_LENGTH_OFFSET + 2
        ]
        != MAIN_TRANSPORT_LENGTH_PWV5
    ):
        raise ColorPatchError("rebuilt MAIN does not use the PWV5 payload byte count")
    return rebuilt, {
        "decompressed_sha256": _sha256(verified.decompressed),
        "compressed_bytes": len(compressed),
        "payload_checksum": f"0x{verified.stored_checksum:04X}",
    }


def compile_bfin_blobs(
    repo_root: Path, toolchain_bin: Path
) -> Tuple[bytes, bytes, bytes, bytes]:
    """Assemble and link the injected routines and fixed-span hooks."""

    assembler = toolchain_bin / "bfin-elf-as"
    linker = toolchain_bin / "bfin-elf-ld"
    objcopy = toolchain_bin / "bfin-elf-objcopy"
    nm = toolchain_bin / "bfin-elf-nm"
    objdump = toolchain_bin / "bfin-elf-objdump"
    for tool in (assembler, linker, objcopy, nm, objdump):
        if not tool.is_file():
            raise ColorPatchError(f"missing Blackfin tool: {tool}")
    source = repo_root / "patches" / "bfin"
    with tempfile.TemporaryDirectory(prefix="nxs-pwv5-bfin-") as directory:
        build = Path(directory)

        def run(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            if result.returncode:
                raise ColorPatchError(result.stderr.strip() or "Blackfin tool failed")
            return result

        run([str(assembler), "-o", str(build / "consumer.o"), str(source / "pwv5_gui.S")])
        run(
            [
                str(linker),
                "-e", "pwv5_gui_consumer",
                "-Ttext=0x00D4A000",
                "--defsym=stock_detail_copy=0x00D49394",
                "-o", str(build / "consumer.elf"),
                str(build / "consumer.o"),
            ]
        )
        run([str(objcopy), "-O", "binary", str(build / "consumer.elf"), str(build / "consumer.bin")])
        consumer_disassembly = run(
            [str(objdump), "-d", str(build / "consumer.elf")]
        ).stdout
        consumer_checks = (
            "CC = BITTST (R7, 0x0)",
            "R7 >>= 0x1",
            "P2=0x1011940",
            "P3 = P3 << 0x1",
            "P2 = P2 + P3",
            "P2 += -0x2",
            "P0=0x1011940",
            "P0 += -0xc",
            "W[P0 + 0x4] = R2",
            "[P4] = R7",
        )
        missing = [item for item in consumer_checks if item not in consumer_disassembly]
        if missing:
            raise ColorPatchError(
                "assembled GUI consumer failed data-flow audit: " + ", ".join(missing)
            )
        symbols = run([str(nm), "-n", str(build / "consumer.elf")]).stdout.splitlines()
        first_copy_address = None
        for line in symbols:
            fields = line.split()
            if len(fields) == 3 and fields[2] == "pwv5_first_copy":
                first_copy_address = int(fields[0], 16)
                break
        if first_copy_address is None:
            raise ColorPatchError("linked GUI blob has no pwv5_first_copy symbol")

        run([str(assembler), "-o", str(build / "call.o"), str(source / "consumer_call_hook.S")])
        run(
            [
                str(linker),
                "-e", "pwv5_consumer_call_hook",
                "-Ttext=0x00D0F538",
                "--defsym=pwv5_gui_consumer=0x00D4A000",
                "-o", str(build / "call.elf"),
                str(build / "call.o"),
            ]
        )
        run([str(objcopy), "-O", "binary", "-j", ".text", str(build / "call.elf"), str(build / "call.bin")])

        run(
            [
                str(assembler),
                "-o", str(build / "first-copy-call.o"),
                str(source / "first_copy_call_hook.S"),
            ]
        )
        run(
            [
                str(linker),
                "-e", "pwv5_first_copy_call_hook",
                "-Ttext=0x00D0FC20",
                f"--defsym=pwv5_first_copy=0x{first_copy_address:08X}",
                "-o", str(build / "first-copy-call.elf"),
                str(build / "first-copy-call.o"),
            ]
        )
        run(
            [
                str(objcopy), "-O", "binary", "-j", ".text",
                str(build / "first-copy-call.elf"),
                str(build / "first-copy-call.bin"),
            ]
        )

        run([str(assembler), "-o", str(build / "renderer.o"), str(source / "renderer_color_load.S")])
        run([str(objcopy), "-O", "binary", "-j", ".text", str(build / "renderer.o"), str(build / "renderer.bin")])
        first_copy_call = (build / "first-copy-call.bin").read_bytes()
        if (
            len(first_copy_call) != 8
            or first_copy_call[:2] != b"\x00\x00"
            or first_copy_call[6:] != b"\x00\x00"
        ):
            raise ColorPatchError("unexpected aligned first-copy call hook")
        return (
            (build / "consumer.bin").read_bytes(),
            (build / "call.bin").read_bytes(),
            first_copy_call[2:6],
            (build / "renderer.bin").read_bytes(),
        )


def build_color_update(
    stock_upd_path: Path,
    output_path: Path,
    repo_root: Path,
    toolchain_bin: Path,
    main_version: bytes = b"1.46",
    gui_version: bytes = b"1.201",
) -> dict:
    """Build a hash-gated full update candidate without flashing it."""

    raw_bytes = CANONICAL_MAX_COLUMNS * 2
    record_bytes = CANONICAL_MAX_COLUMNS * RECORD_STRIDE
    if max(raw_bytes, record_bytes) > RECORD_ARENA_CLEAR_BYTES:
        raise ColorPatchError("canonical PWV5 transform exceeds the proven record arena")

    stock = parse_upd(stock_upd_path.read_bytes())
    consumer, call_hook, first_copy_hook, renderer_load = compile_bfin_blobs(
        repo_root, toolchain_bin
    )
    gui = patch_gui_segment(
        stock.segments["GUI"],
        consumer,
        call_hook,
        first_copy_hook,
        renderer_load,
        gui_version,
    )
    main, main_summary = rebuild_main_segment(stock.segments["MAIN"], main_version)
    segments = [gui, stock.segments["DRIV"], main, stock.segments["PANL"]]
    candidate = build_upd(segments)
    verified = parse_upd(candidate)
    crc_results = {
        name: verify_segment_crc(name, verified.segments[name]).valid
        for name in SEGMENT_NAMES
    }
    if not all(crc_results.values()):
        raise ColorPatchError("candidate update failed segment CRC verification")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(candidate)
    manifest = {
        "schema": 1,
        "status": "offline experimental candidate; NOT hardware-approved",
        "stock_path": str(stock_upd_path.resolve()),
        "stock_sha256": _sha256(stock_upd_path.read_bytes()),
        "output_path": str(output_path.resolve()),
        "output_sha256": _sha256(candidate),
        "versions": {
            "main": main_version.decode("ascii"),
            "gui": gui_version.decode("ascii"),
        },
        "main": {
            "tag_patches": [
                f"0x{0xA4000000 + offset:08X}: PWV3 -> PWV5"
                for offset in MAIN_TAG_OFFSETS
            ],
            "transport_length_patch": (
                "0xA425B9EA: descriptor entry count (+0) -> payload byte count (+8)"
            ),
            **main_summary,
        },
        "gui": {
            "stock_sha256": STOCK_GUI_SHA256,
            "patched_sha256": _sha256(gui),
            "consumer_address": f"0x{GUI_INJECTION_ADDRESS:08X}",
            "consumer_bytes": len(consumer),
            "completion_call_hook": f"0x{GUI_CONSUMER_CALL_ADDRESS:08X}",
            "first_copy_call_hook": f"0x{GUI_FIRST_COPY_CALL_ADDRESS:08X}",
            "receiver_buffer_hooks": [
                f"0x{GUI_FIRST_BUFFER_ADDRESS:08X}",
                f"0x{GUI_EXTENSION_BUFFER_ADDRESS:08X}",
            ],
            "renderer_buffer_hook": f"0x{GUI_RENDERER_BUFFER_ADDRESS:08X}",
            "renderer_load_hook": f"0x{GUI_RENDERER_LOAD_ADDRESS:08X}",
            "maximum_columns": CANONICAL_MAX_COLUMNS,
            "record_arena": {
                "base": f"0x{RECORD_ARENA_BASE:08X}",
                "end_exclusive": f"0x{RECORD_ARENA_END:08X}",
                "proven_clear_bytes": RECORD_ARENA_CLEAR_BYTES,
                "raw_input_bytes": raw_bytes,
                "expanded_record_bytes": record_bytes,
            },
            "buffer_strategy": (
                "receive into 0x01011940 and expand backwards into 12-byte records; "
                "RGB555 is record +4"
            ),
        },
        "verification": {
            "segment_crc": crc_results,
            "container_sizes": dict(verified.sizes),
        },
        "hardware_gates_remaining": [
            "prove stock/rebuilt update and recovery loop on the sacrificial deck",
            "prove a no-op GUI injection before enabling PWV5 hooks",
            "measure 68-frame command-32 transfer timing",
            "confirm renderer index alignment during zoom, seek, and unload",
            "confirm no concurrent record-arena owner races a partial transfer",
        ],
    }
    manifest_path = output_path.with_suffix(output_path.suffix + ".json")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest
