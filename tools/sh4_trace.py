#!/usr/bin/env python3
"""Reproducible, read-only SH-4 tag/xref tracing for decompressed MAIN images.

The scanner deliberately separates byte-level facts from control-flow inferences.
It does not modify the input image and it does not claim that a tag comparison is a
payload handler.  GNU objdump is used as the authoritative human-readable decoder;
the small local decoder is used only for deterministic cross-reference extraction.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence


DEFAULT_BASE = 0xA4000000
ADDRESS_MASK = 0x1FFFFFFF
KNOWN_PWV3_LOOKUPS = (
    0xA42ADE42,
    0xA42AE438,
    0xA42AE66E,
    0xA42AEE58,
)
KNOWN_COMPARE = 0x04388E5C
STOCK_V144_SHA256 = "f73da28a7886955c879748c63052fb199d966aaa133f4fd5c9d27065b6301d4f"
PROLOGUE_STS_PR = 0x4F22
RTS = 0x000B


class TraceError(ValueError):
    """Raised when a requested trace cannot be performed safely."""


def canonical_address(address: int) -> int:
    """Collapse SH P0/P1/P2 cached aliases to their 29-bit physical address."""

    return address & ADDRESS_MASK


def addresses_equivalent(left: int, right: int) -> bool:
    return canonical_address(left) == canonical_address(right)


def parse_int(value: str) -> int:
    return int(value, 0)


def read_u16(image: bytes, offset: int) -> int:
    return struct.unpack_from("<H", image, offset)[0]


def read_u32(image: bytes, offset: int) -> int:
    return struct.unpack_from("<I", image, offset)[0]


def runtime_to_offset(address: int, base: int, image_length: int) -> Optional[int]:
    offset = address - base
    return offset if 0 <= offset < image_length else None


def pc_literal_address(instruction_address: int, word: int) -> Optional[int]:
    """Return the address read by MOV.L @(disp,PC),Rn, if ``word`` is one."""

    if word >> 12 != 0xD:
        return None
    return ((instruction_address + 4) & ~3) + (word & 0xFF) * 4


def direct_bsr_target(instruction_address: int, word: int) -> Optional[int]:
    if word >> 12 != 0xB:
        return None
    displacement = word & 0xFFF
    if displacement & 0x800:
        displacement -= 0x1000
    return instruction_address + 4 + displacement * 2


def jsr_register(word: int) -> Optional[int]:
    return (word >> 8) & 0xF if word & 0xF0FF == 0x400B else None


def bsrf_register(word: int) -> Optional[int]:
    return (word >> 8) & 0xF if word & 0xF0FF == 0x0003 else None


def destination_register(word: int) -> Optional[int]:
    """Return Rn for common instructions that overwrite a whole register.

    This intentionally covers only forms needed to reject stale literal-load
    resolutions. Unknown instructions make the indirect result less confident but
    never manufacture a target.
    """

    top = word >> 12
    if top in (0x5, 0x6, 0x7, 0x9, 0xD, 0xE):
        return (word >> 8) & 0xF
    if word & 0xF00F in (0x300C, 0x300E, 0x300F, 0x3008, 0x300A, 0x300B):
        return (word >> 8) & 0xF
    return None


@dataclass(frozen=True)
class PointerReference:
    address: int
    stored_value: int
    alignment: int


@dataclass(frozen=True)
class LiteralLoad:
    instruction: int
    register: int
    literal: int
    value: int


@dataclass(frozen=True)
class CallReference:
    instruction: int
    target: int
    kind: str
    register: Optional[int] = None
    literal: Optional[int] = None


@dataclass(frozen=True)
class FunctionRange:
    start: int
    end: int
    confidence: str


@dataclass(frozen=True)
class TagComparison:
    tag: str
    tag_address: int
    load_site: int
    literal_address: int
    compare_call: Optional[int]
    compare_target: Optional[int]
    length_is_four: bool


@dataclass(frozen=True)
class ConstantBuild:
    """A small immediate assembled in one SH-4 register.

    ``operations`` contains the instruction addresses that contributed to the
    final value.  The scanner is intended for structure offsets such as the
    PWV3 handler's split ``0xE48``/``0xE50`` constants, not arbitrary symbolic
    execution.
    """

    address: int
    register: int
    value: int
    operations: tuple[int, ...]


def find_tag_occurrences(image: bytes, base: int, tag: bytes) -> List[int]:
    if len(tag) != 4:
        raise TraceError("ANLZ tags must be exactly four bytes")
    found: List[int] = []
    cursor = 0
    while True:
        offset = image.find(tag, cursor)
        if offset < 0:
            return found
        found.append(base + offset)
        cursor = offset + 1


def scan_pointer_references(
    image: bytes, base: int, target: int, alignment: int = 2
) -> List[PointerReference]:
    if alignment not in (1, 2, 4):
        raise TraceError("pointer alignment must be 1, 2, or 4")
    references: List[PointerReference] = []
    for offset in range(0, len(image) - 3, alignment):
        value = read_u32(image, offset)
        if addresses_equivalent(value, target):
            references.append(PointerReference(base + offset, value, alignment))
    return references


def scan_literal_loads(
    image: bytes, base: int, target: Optional[int] = None
) -> List[LiteralLoad]:
    loads: List[LiteralLoad] = []
    for offset in range(0, len(image) - 1, 2):
        word = read_u16(image, offset)
        literal = pc_literal_address(base + offset, word)
        if literal is None:
            continue
        literal_offset = runtime_to_offset(literal, base, len(image))
        if literal_offset is None or literal_offset + 4 > len(image):
            continue
        value = read_u32(image, literal_offset)
        if target is None or addresses_equivalent(value, target):
            loads.append(
                LiteralLoad(base + offset, (word >> 8) & 0xF, literal, value)
            )
    return loads


def scan_direct_calls(image: bytes, base: int, target: int) -> List[CallReference]:
    calls: List[CallReference] = []
    for offset in range(0, len(image) - 1, 2):
        resolved = direct_bsr_target(base + offset, read_u16(image, offset))
        if resolved is not None and addresses_equivalent(resolved, target):
            calls.append(CallReference(base + offset, resolved, "bsr"))
    return calls


def _resolve_register_literal(
    image: bytes, base: int, call_offset: int, register: int, window: int = 32
) -> Optional[LiteralLoad]:
    lower = max(0, call_offset - window * 2)
    for offset in range(call_offset - 2, lower - 1, -2):
        word = read_u16(image, offset)
        if word >> 12 == 0xD and ((word >> 8) & 0xF) == register:
            literal = pc_literal_address(base + offset, word)
            assert literal is not None
            literal_offset = runtime_to_offset(literal, base, len(image))
            if literal_offset is None or literal_offset + 4 > len(image):
                return None
            return LiteralLoad(
                base + offset, register, literal, read_u32(image, literal_offset)
            )
        if destination_register(word) == register:
            return None
        # Do not carry a register value backwards through a control-flow boundary.
        if direct_bsr_target(base + offset, word) is not None or word == RTS:
            return None
    return None


def resolve_calls_linear(
    image: bytes, base: int, function: FunctionRange
) -> dict[int, int]:
    """Resolve simple register and stack-spilled constants inside one function.

    The NXS tag validators load ``strncmp`` once, spill it to a fixed stack slot,
    and reload it for later comparisons. This pass models precisely those MOV/ADD
    forms. It is deliberately not a general SH emulator and its results are only
    used where the call register contains a concrete literal-derived value.
    """

    registers: List[Optional[int]] = [None] * 16
    stack: dict[int, int] = {}
    calls: dict[int, int] = {}
    start = max(0, function.start - base)
    end = min(len(image), function.end - base)

    for offset in range(start, end - 1, 2):
        address = base + offset
        word = read_u16(image, offset)
        top = word >> 12
        n = (word >> 8) & 0xF
        m = (word >> 4) & 0xF

        register = jsr_register(word)
        if register is not None and registers[register] is not None:
            calls[address] = registers[register]  # type: ignore[assignment]
            continue

        literal = pc_literal_address(address, word)
        if literal is not None:
            literal_offset = runtime_to_offset(literal, base, len(image))
            registers[n] = (
                read_u32(image, literal_offset)
                if literal_offset is not None and literal_offset + 4 <= len(image)
                else None
            )
            continue

        if top == 0xE:  # mov #imm,rn
            immediate = word & 0xFF
            registers[n] = immediate - 0x100 if immediate & 0x80 else immediate
            continue
        if top == 0x7:  # add #imm,rn
            immediate = word & 0xFF
            immediate = immediate - 0x100 if immediate & 0x80 else immediate
            registers[n] = (
                registers[n] + immediate if registers[n] is not None else None
            )
            continue
        if word & 0xF00F == 0x6003:  # mov rm,rn
            registers[n] = registers[m]
            continue
        if word & 0xF00F == 0x0006:  # mov.l rm,@(r0,rn)
            if n == 15 and registers[0] is not None and registers[m] is not None:
                stack[registers[0]] = registers[m]
            continue
        if word & 0xF00F == 0x000E:  # mov.l @(r0,rm),rn
            if m == 15 and registers[0] is not None:
                registers[n] = stack.get(registers[0])
            else:
                registers[n] = None
            continue
        if top == 0x1:  # mov.l rm,@(disp,rn)
            displacement = (word & 0xF) * 4
            if n == 15 and registers[m] is not None:
                stack[displacement] = registers[m]
            continue
        if top == 0x5:  # mov.l @(disp,rm),rn
            displacement = (word & 0xF) * 4
            registers[n] = stack.get(displacement) if m == 15 else None
            continue

        written = destination_register(word)
        if written is not None:
            registers[written] = None
    return calls


def scan_indirect_calls(
    image: bytes, base: int, target: Optional[int] = None
) -> List[CallReference]:
    calls: List[CallReference] = []
    for offset in range(0, len(image) - 1, 2):
        word = read_u16(image, offset)
        register = jsr_register(word)
        if register is None:
            continue
        load = _resolve_register_literal(image, base, offset, register)
        if load is None:
            continue
        if target is None or addresses_equivalent(load.value, target):
            calls.append(
                CallReference(
                    base + offset,
                    load.value,
                    "jsr_literal",
                    register,
                    load.literal,
                )
            )
    return calls


def scan_constructed_constants(
    image: bytes,
    base: int,
    targets: Iterable[int],
    max_instruction_span: int = 16,
) -> List[ConstantBuild]:
    """Find ``mov #imm``/shift/``add #imm`` constants with interleaving.

    GCC's SH-4 output frequently creates offsets by loading an 8-bit immediate,
    shifting it by 8 or 16 bits, and adding another signed immediate.  Unrelated
    instructions may appear between those operations.  Per-register state is
    retained across such instructions, but discarded when the register is
    overwritten or the build grows beyond ``max_instruction_span``.

    Results are candidates: scanning a flat firmware image also visits literal
    pools and data.  Callers must corroborate a hit with authoritative GNU
    disassembly before treating it as code.
    """

    wanted = set(targets)
    if max_instruction_span < 1:
        raise TraceError("constant-build instruction span must be positive")

    # Each state is (value, contributing instruction addresses).
    states: List[Optional[tuple[int, tuple[int, ...]]]] = [None] * 16
    results: List[ConstantBuild] = []

    for offset in range(0, len(image) - 1, 2):
        address = base + offset
        word = read_u16(image, offset)
        top = word >> 12
        n = (word >> 8) & 0xF

        for register, state in enumerate(states):
            if state is None:
                continue
            if address - state[1][0] > max_instruction_span * 2:
                states[register] = None

        changed_register: Optional[int] = None
        if top == 0xE:  # mov #imm,rn
            immediate = word & 0xFF
            immediate = immediate - 0x100 if immediate & 0x80 else immediate
            states[n] = (immediate, (address,))
            changed_register = n
        elif top == 0x7:  # add #imm,rn
            state = states[n]
            if state is not None:
                immediate = word & 0xFF
                immediate = immediate - 0x100 if immediate & 0x80 else immediate
                states[n] = (state[0] + immediate, state[1] + (address,))
                changed_register = n
            else:
                states[n] = None
        elif word & 0xF0FF in (0x4000, 0x4008, 0x4018, 0x4028):
            # shll, shll2, shll8, shll16
            shifts = {0x4000: 1, 0x4008: 2, 0x4018: 8, 0x4028: 16}
            register = (word >> 8) & 0xF
            state = states[register]
            if state is not None:
                shift = shifts[word & 0xF0FF]
                states[register] = (state[0] << shift, state[1] + (address,))
                changed_register = register
        else:
            written = destination_register(word)
            if written is not None:
                states[written] = None

        if changed_register is None:
            continue
        state = states[changed_register]
        if state is not None and state[0] in wanted:
            results.append(
                ConstantBuild(address, changed_register, state[0], state[1])
            )

    return results


def find_function_range(
    image: bytes,
    base: int,
    site: int,
    backward_limit: int = 0x2000,
    forward_limit: int = 0x4000,
) -> FunctionRange:
    site_offset = runtime_to_offset(site, base, len(image))
    if site_offset is None:
        raise TraceError(f"site 0x{site:X} is outside the image")

    start_offset: Optional[int] = None
    for offset in range(site_offset & ~1, max(-1, site_offset - backward_limit), -2):
        if read_u16(image, offset) == PROLOGUE_STS_PR:
            start_offset = offset
            break
    if start_offset is None:
        start_offset = max(0, site_offset - backward_limit)
        confidence = "low: no sts.l pr,@-r15 prologue found"
    else:
        # GCC normally saves R9-R14 immediately before PR. The first register
        # push, rather than the PR save, is the externally referenced entry.
        while start_offset >= 2:
            previous = read_u16(image, start_offset - 2)
            if previous & 0xFF0F != 0x2F06:  # mov.l Rm,@-R15
                break
            start_offset -= 2
        confidence = "heuristic: register-save prologue through next rts"

    end_offset: Optional[int] = None
    stop = min(len(image) - 2, site_offset + forward_limit)
    for offset in range(site_offset & ~1, stop + 1, 2):
        if read_u16(image, offset) == RTS:
            end_offset = min(len(image), offset + 4)
            break
    if end_offset is None:
        end_offset = stop + 2
        confidence = "low: no rts found within scan window"
    return FunctionRange(base + start_offset, base + end_offset, confidence)


def _ascii_fourcc_at(image: bytes, base: int, address: int) -> Optional[str]:
    offset = runtime_to_offset(address, base, len(image))
    if offset is None or offset + 4 > len(image):
        return None
    raw = image[offset : offset + 4]
    if not all(0x20 <= value <= 0x7E for value in raw):
        return None
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return None


def _find_nearby_compare_call(
    image: bytes, base: int, load: LiteralLoad, instruction_count: int = 6
) -> tuple[Optional[int], Optional[int], bool]:
    load_offset = load.instruction - base
    compare_call: Optional[int] = None
    compare_target: Optional[int] = None
    length_is_four = False
    for offset in range(load_offset + 2, min(len(image) - 1, load_offset + instruction_count * 2 + 2), 2):
        word = read_u16(image, offset)
        if word == 0xE604:  # mov #4,r6
            length_is_four = True
        register = jsr_register(word)
        if register is not None and compare_call is None:
            resolved = _resolve_register_literal(image, base, offset, register)
            compare_call = base + offset
            compare_target = resolved.value if resolved else None
    return compare_call, compare_target, length_is_four


def enumerate_tag_comparisons(
    image: bytes, base: int, function: FunctionRange
) -> List[TagComparison]:
    comparisons: List[TagComparison] = []
    resolved_calls = resolve_calls_linear(image, base, function)
    start = max(0, function.start - base)
    end = min(len(image), function.end - base)
    for offset in range(start, end - 1, 2):
        word = read_u16(image, offset)
        literal = pc_literal_address(base + offset, word)
        if literal is None:
            continue
        literal_offset = runtime_to_offset(literal, base, len(image))
        if literal_offset is None or literal_offset + 4 > len(image):
            continue
        value = read_u32(image, literal_offset)
        fourcc = _ascii_fourcc_at(image, base, value)
        if fourcc is None:
            continue
        load = LiteralLoad(base + offset, (word >> 8) & 0xF, literal, value)
        call, compare_target, length_is_four = _find_nearby_compare_call(
            image, base, load
        )
        if call is not None and compare_target is None:
            compare_target = resolved_calls.get(call)
        if call is None or not length_is_four:
            continue
        comparisons.append(
            TagComparison(
                fourcc,
                value,
                load.instruction,
                load.literal,
                call,
                compare_target,
                length_is_four,
            )
        )
    return comparisons


def find_objdump(explicit: Optional[Path] = None) -> Optional[Path]:
    candidates: Iterable[Optional[Path]] = (
        explicit,
        Path("work/toolchain/sh-elf/bin/sh-elf-objdump"),
        Path("/opt/toolchains/dc/sh-elf/bin/sh-elf-objdump"),
        Path(shutil.which("sh-elf-objdump")) if shutil.which("sh-elf-objdump") else None,
    )
    for candidate in candidates:
        if candidate is not None and candidate.is_file():
            return candidate.resolve()
    return None


def objdump_range(
    objdump: Path, image_path: Path, base: int, start: int, end: int
) -> str:
    command = [
        str(objdump),
        "-D",
        "-b",
        "binary",
        "-m",
        "sh4",
        "-EL",
        f"--adjust-vma=0x{base:X}",
        f"--start-address=0x{start:X}",
        f"--stop-address=0x{end:X}",
        str(image_path),
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode:
        raise TraceError(
            f"objdump failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout


def verify_objdump(output: str) -> dict:
    """Verify the known bounded string-compare routine from GNU output."""

    lowered = output.lower()
    checks = {
        "routine_address": "a4388e5c" in lowered,
        "tests_length": bool(re.search(r"tst\s+r6\s*,\s*r6", lowered)),
        "loads_bytes": lowered.count("mov.b") >= 4,
        "returns": lowered.count("rts") >= 2,
        "subtracts_bytes": bool(re.search(r"sub\s+r7\s*,\s*r0", lowered)),
    }
    checks["verified"] = all(checks.values())
    return checks


def _hex(value: Optional[int]) -> Optional[str]:
    return None if value is None else f"0x{value:08X}"


def _serialise_dataclass(item) -> dict:
    result = asdict(item)
    for key, value in tuple(result.items()):
        if key in {
            "address",
            "stored_value",
            "instruction",
            "target",
            "literal",
            "start",
            "end",
            "tag_address",
            "load_site",
            "literal_address",
            "compare_call",
            "compare_target",
        } and isinstance(value, int):
            result[key] = _hex(value)
    return result


def inspect_anlz_pwv3(path: Path) -> dict:
    """Read the canonical PWV3 header without depending on third-party modules."""

    data = path.read_bytes()
    if len(data) < 28 or data[:4] != b"PMAI":
        raise TraceError(f"{path} is not a PMAI/ANLZ file")
    header_length, file_length = struct.unpack_from(">II", data, 4)
    if header_length < 12 or file_length > len(data):
        raise TraceError(f"{path} has invalid PMAI lengths")
    offset = header_length
    while offset + 12 <= file_length:
        kind, tag_header, tag_length = struct.unpack_from(">4sII", data, offset)
        if tag_header < 12 or tag_length < tag_header or offset + tag_length > file_length:
            raise TraceError(f"{path} has an invalid tag at 0x{offset:X}")
        if kind == b"PWV3":
            if tag_header < 24:
                raise TraceError("PWV3 header is shorter than 24 bytes")
            entry_size, entry_count, unknown = struct.unpack_from(">III", data, offset + 12)
            payload_length = tag_length - tag_header
            return {
                "path": str(path.resolve()),
                "offset": _hex(offset),
                "header_length": tag_header,
                "tag_length": tag_length,
                "entry_size": entry_size,
                "entry_count": entry_count,
                "unknown": _hex(unknown),
                "payload_offset": _hex(offset + tag_header),
                "payload_length": payload_length,
                "size_product_matches_payload": entry_size * entry_count == payload_length,
            }
        offset += tag_length
    raise TraceError(f"PWV3 is absent from {path}")


def recover_stock_pwv3_dataflow(image: bytes, base: int, digest: str) -> dict:
    """Return the address-backed v1.44 PWV3 chain.

    This is deliberately gated by the complete stock-image hash.  The statements
    below are stable annotations for verified GNU disassembly, not symbols claimed
    to apply to an arbitrary firmware revision.
    """

    if digest != STOCK_V144_SHA256 or base != DEFAULT_BASE:
        return {
            "available": False,
            "reason": "extended annotations require stock v1.44 at 0xA4000000",
        }

    tag_table_address = 0xA40ACF6C
    table_offset = runtime_to_offset(tag_table_address, base, len(image))
    assert table_offset is not None
    tag_table = []
    for index in range(12):
        pointer = read_u32(image, table_offset + index * 4)
        tag_table.append(
            {"index": index, "tag": _ascii_fourcc_at(image, base, pointer), "address": _hex(pointer)}
        )

    return {
        "available": True,
        "baseline": "stock CDJ-2000NXS v1.44",
        "tag_index_dispatch": {
            "pointer_table": _hex(tag_table_address),
            "entries": tag_table,
            "classifier": _hex(0xA42B2F1A),
            "classifier_call": _hex(0xA42BAD48),
            "pwv3_index": 8,
            "pwv3_branch": _hex(0xA42BB650),
            "confidence": "verified",
            "evidence": "GNU disassembly copies 12 pointers, compares four bytes, returns the pointer index, then dispatches index 8 to 0xA42BB650.",
        },
        "legacy_lookup_callers": [
            {
                "validator": _hex(0xA42ADC74),
                "caller": _hex(0xA42AD594),
                "wrapper": _hex(0xA4182C20),
                "request_id": _hex(0x13E0),
            },
            {
                "validator": _hex(0xA42AE240),
                "caller": _hex(0xA42AD780),
                "wrapper": _hex(0xA4182CD2),
                "request_id": _hex(0x13E1),
            },
            {
                "validator": _hex(0xA42AEC10),
                "caller": _hex(0xA42AD9EA),
                "wrapper": _hex(0xA4182D70),
                "request_id": _hex(0x13E2),
            },
        ],
        "pwv3_handler": {
            "range": {"start": _hex(0xA42BB650), "end": _hex(0xA42BB7D6)},
            "owner_tag_locator": {"offset": _hex(0x12C0), "confidence": "inferred"},
            "owner_descriptor": {"offset": _hex(0x12C8), "size": 24, "confidence": "verified"},
            "stream_object": {"offset": _hex(0x1DB4), "confidence": "verified"},
            "fields": [
                {"offset": 0, "type": "char[4]", "meaning": "tag", "confidence": "verified"},
                {"offset": 4, "type": "u32", "meaning": "len_header", "confidence": "verified"},
                {"offset": 8, "type": "u32", "meaning": "len_tag", "confidence": "verified"},
                {"offset": 12, "type": "u16", "meaning": "reserved/unknown high half", "confidence": "verified"},
                {"offset": 14, "type": "u16", "meaning": "entry_size", "confidence": "verified"},
                {"offset": 16, "type": "u32", "meaning": "entry_count", "confidence": "verified"},
                {"offset": 20, "type": "u16", "meaning": "unknown word 1", "confidence": "verified"},
                {"offset": 22, "type": "u16", "meaning": "zeroed/unknown word 2", "confidence": "verified"},
            ],
            "endian_readers": [
                {"address": _hex(0xA42B315C), "width": 2},
                {"address": _hex(0xA42B31B4), "width": 4},
            ],
            "payload_length_site": _hex(0xA42BB79A),
            "payload_stream_helper": _hex(0xA42B3352),
            "payload_action": "validate/advance stream by entry_size * entry_count",
            "allocation_or_copy": "none observed while indexing; only the 24-byte descriptor is zeroed and populated",
            "confidence": "verified except the semantic name of owner+0x12C0",
        },
        "database_wave_path": {
            "get_wave_data": _hex(0xA4149632),
            "get_wave_call_sites": [_hex(0xA41721EE), _hex(0xA41722D2)],
            "result_copy_size": 900,
            "result_destination_offset": 112,
            "registration_calls": [
                {"kind": "disc", "address": _hex(0xA414984A), "call": _hex(0xA417209C)},
                {"kind": "sd_usb", "address": _hex(0xA414978A), "call": _hex(0xA4172114)},
            ],
            "confidence": "verified call and copy sites; role names are anchored by firmware debug strings",
        },
        "legacy_wave_gui_boundary": {
            "request_operation": _hex(0xA426017E),
            "cache_lookup": _hex(0xA4336DDC),
            "cache_pool": _hex(0x05560698),
            "cache_record_count": 20,
            "cache_record_stride": _hex(0x8B0),
            "cache_payload_offset": 40,
            "cache_payload_size": 900,
            "staging_buffer": _hex(0x04985D64),
            "staging_copy_call": _hex(0xA4260378),
            "wave_builder": _hex(0xA4260C82),
            "wave_builder_call": _hex(0xA42603B2),
            "message_buffer": _hex(0x049854F4),
            "message_id_offset": 112,
            "message_id": 4,
            "record_count_offset": 114,
            "payload_offset": 120,
            "payload_element_type": "u16 words",
            "payload_bytes_offset": 28,
            "total_bytes_offset": 32,
            "source_segments": [800, 100],
            "debug_string": "GU operation: WAVE[%d,%d]",
            "representation": "legacy 900-byte WAVE/CWCASH data transformed into 16-bit fields",
            "pwv3_link": "not proven",
            "confidence": "verified addresses, sizes, message writes, and WAVE/CWCASH semantics; the upstream command-routing link to dbcl_GetWaveData remains inferred",
        },
        "cue_overlay_gui_boundary": {
            "response_loader": _hex(0xA4336070),
            "response_payload_offset": 112,
            "response_payload_size": _hex(0xE7C),
            "response_to_working_copy": _hex(0xA43361AC),
            "working_table": _hex(0x0556C858),
            "working_to_canonical_copy": _hex(0xA4334FE0),
            "canonical_table": _hex(0x0556B458),
            "ready_flag": _hex(0x0556C2D4),
            "table_initializer": _hex(0xA4336AAE),
            "record_size": 36,
            "record_count": 103,
            "table_size": _hex(0xE7C),
            "gui_staging_buffer": _hex(0x049860F0),
            "canonical_to_gui_copy": _hex(0xA426087A),
            "cue_builder": _hex(0xA4260D94),
            "cue_builder_call": _hex(0xA42608B8),
            "message_buffer": _hex(0x049854F4),
            "message_id_offset": 112,
            "message_id": 5,
            "record_count_offset": 114,
            "payload_offset": 120,
            "record_input_stride": 36,
            "record_loop_limit": 100,
            "sample_helper": _hex(0xA42A6EEA),
            "debug_semantics": "CUEWAV/CUE marker data",
            "pwv3_link": "not a PWV3 payload path",
            "confidence": "verified complete staging chain and cue semantics",
        },
        "pwv3_payload_accessor": {
            "address": _hex(0xA42AC380),
            "call": _hex(0xA418285C),
            "owner_locator_offset": _hex(0x12C0),
            "descriptor_fields_read": {
                "len_header": _hex(0x12CC),
                "entry_size": _hex(0x12D6),
                "entry_count": _hex(0x12D8),
                "unknown_word": _hex(0x12DC),
            },
            "result_layout": [
                {"offset": 0, "meaning": "entry_count"},
                {"offset": 4, "meaning": "entry_size"},
                {"offset": 8, "meaning": "payload byte count"},
                {"offset": 12, "meaning": "descriptor unknown word"},
                {"offset": 16, "meaning": "allocated PWV3 payload pointer"},
            ],
            "seek_or_read_setup": _hex(0xA42193A6),
            "allocation": _hex(0xA4219B3C),
            "clear": _hex(0xA4388BA0),
            "read": _hex(0xA42194FE),
            "payload_address_expression": "saved locator + len_header",
            "payload_byte_count_expression": "entry_size * entry_count",
            "confidence": "verified direct data flow",
        },
        "partial_wave_request_path": {
            "accessor_wrapper": _hex(0xA4182800),
            "accessor_call": _hex(0xA418285C),
            "internal_result_sender": _hex(0xA419530C),
            "internal_command": _hex(0x2015),
            "named_api": "dbcl_GetParWaveData",
            "named_api_address": _hex(0xA414ADBC),
            "database_request": _hex(0x2904),
            "database_response": _hex(0x4A02),
            "service_handler": _hex(0xA417234E),
            "public_request": _hex(0x42E),
            "public_dispatch": _hex(0xA4164910),
            "response_payload_pointer_offset": 44,
            "response_entry_count_offset": 48,
            "gui_loader": _hex(0xA4335EF6),
            "gui_response": _hex(0x13B5),
            "global_payload_pointer": _hex(0x0556D9F8),
            "global_entry_count": _hex(0x0556D9FC),
            "track_owner_stager": _hex(0xA433702E),
            "track_payload_object_offset": _hex(0x5A4),
            "track_entry_count_offset": _hex(0x5A8),
            "confidence": "verified; API role is anchored by firmware debug strings",
        },
        "detailed_wave_gui_boundary": {
            "debug_semantics": "GU send: detailed waveform",
            "message_buffer": _hex(0x04985564),
            "header_constructor": _hex(0xA425B8E0),
            "header_constructor_call": _hex(0xA425EC0A),
            "first_chunk_constructor": _hex(0xA425BD60),
            "first_chunk_call": _hex(0xA425AA28),
            "extension_constructor": _hex(0xA425C0CC),
            "extension_calls": [_hex(0xA425AA7E), _hex(0xA425885C)],
            "message_word_0": 32,
            "frame_size": 896,
            "trailer_offset": _hex(0x37E),
            "trailer_size": 2,
            "trailer_function": _hex(0xA4310FC0),
            "first_payload_offset": 14,
            "first_payload_maximum": 880,
            "extension_payload_offset": 6,
            "extension_payload_maximum": 888,
            "source_pointer_path": "track object+0x5A4 -> result object+16 -> allocated PWV3 payload",
            "outbound_representation": "raw PWV3 bytes",
            "physical_transport_edge": "the shared-buffer constructors and scheduling calls are identified; the final generic send-to-physical SPORT/DMA serialization is not yet independently proven",
            "confidence": "verified through direct loads and byte-copy loops; physical transport edge unresolved",
        },
    }


def build_trace(
    image_path: Path,
    base: int = DEFAULT_BASE,
    tag: str = "PWV3",
    lookup_sites: Sequence[int] = KNOWN_PWV3_LOOKUPS,
    objdump_path: Optional[Path] = None,
    anlz_path: Optional[Path] = None,
) -> tuple[dict, dict[str, str]]:
    image = image_path.read_bytes()
    digest = hashlib.sha256(image).hexdigest()
    raw_tag = tag.encode("ascii")
    occurrences = find_tag_occurrences(image, base, raw_tag)
    if not occurrences:
        raise TraceError(f"{tag} is absent from {image_path}")

    functions: List[FunctionRange] = []
    for site in lookup_sites:
        if runtime_to_offset(site, base, len(image)) is None:
            continue
        function = find_function_range(image, base, site)
        if function not in functions:
            functions.append(function)

    comparisons = {
        f"0x{function.start:08X}": [
            _serialise_dataclass(item)
            for item in enumerate_tag_comparisons(image, base, function)
        ]
        for function in functions
    }

    lookup_details = []
    for site in lookup_sites:
        offset = runtime_to_offset(site, base, len(image))
        if offset is None or offset + 2 > len(image):
            lookup_details.append({"site": _hex(site), "verified": False})
            continue
        word = read_u16(image, offset)
        literal = pc_literal_address(site, word)
        literal_offset = (
            runtime_to_offset(literal, base, len(image)) if literal is not None else None
        )
        value = (
            read_u32(image, literal_offset)
            if literal_offset is not None and literal_offset + 4 <= len(image)
            else None
        )
        load = (
            LiteralLoad(site, (word >> 8) & 0xF, literal, value)
            if literal is not None and value is not None
            else None
        )
        call, target, length_four = (
            _find_nearby_compare_call(image, base, load) if load else (None, None, False)
        )
        if call is not None and target is None:
            containing = next(
                (
                    function
                    for function in functions
                    if function.start <= site < function.end
                ),
                None,
            )
            if containing is not None:
                target = resolve_calls_linear(image, base, containing).get(call)
        lookup_details.append(
            {
                "site": _hex(site),
                "literal": _hex(literal),
                "tag_address": _hex(value),
                "tag_text": _ascii_fourcc_at(image, base, value) if value else None,
                "compare_call": _hex(call),
                "compare_target": _hex(target),
                "length_is_four": length_four,
                "verified": bool(
                    value is not None
                    and addresses_equivalent(value, occurrences[0])
                    and target is not None
                    and addresses_equivalent(target, KNOWN_COMPARE)
                    and length_four
                ),
            }
        )

    direct_callers = []
    indirect_callers = []
    pointer_tables = []
    for function in functions:
        direct_callers.extend(scan_direct_calls(image, base, function.start))
        indirect_callers.extend(scan_indirect_calls(image, base, function.start))
        pointer_tables.extend(scan_pointer_references(image, base, function.start, 2))

    disassemblies: dict[str, str] = {}
    objdump = find_objdump(objdump_path)
    objdump_verification = {"available": False, "verified": False}
    if objdump:
        compare_text = objdump_range(
            objdump, image_path, base, 0xA4388E5C, 0xA4388E90
        )
        disassemblies["compare_0xA4388E5C"] = compare_text
        objdump_verification = {
            "available": True,
            "path": str(objdump),
            **verify_objdump(compare_text),
        }
        for function in functions:
            key = f"function_0x{function.start:08X}"
            disassemblies[key] = objdump_range(
                objdump, image_path, base, function.start, function.end
            )
        if digest == STOCK_V144_SHA256 and base == DEFAULT_BASE and tag == "PWV3":
            stock_ranges = {
                "tag_index_classifier": (0xA42B2F1A, 0xA42B2FAE),
                "pwv3_handler": (0xA42BB650, 0xA42BB7D6),
                "pwv3_payload_accessor": (0xA42AC380, 0xA42AC5B4),
                "stream_helpers": (0xA42B315C, 0xA42B3454),
                "dbcl_get_wave": (0xA4149632, 0xA414978A),
                "dbcl_get_par_wave": (0xA414ADBC, 0xA414AE7E),
                "db_wave_consumers": (0xA4171FAC, 0xA417234E),
                "par_wave_service": (0xA417234E, 0xA4172498),
                "par_wave_gui_loader": (0xA4335EF6, 0xA4336070),
                "par_wave_track_stager": (0xA433702E, 0xA43371A0),
                "detailed_wave_header": (0xA425B8E0, 0xA425BA48),
                "detailed_wave_first_chunk": (0xA425BD60, 0xA425C0CC),
                "detailed_wave_extension": (0xA425C0CC, 0xA425C386),
                "legacy_wave_builder": (0xA4260C82, 0xA4260D94),
                "cue_builder": (0xA4260D94, 0xA42611EA),
                "gui_wave_clear_builder": (0xA42621CC, 0xA4262274),
            }
            for name, (start, end) in stock_ranges.items():
                disassemblies[name] = objdump_range(
                    objdump, image_path, base, start, end
                )

    stock_dataflow = (
        recover_stock_pwv3_dataflow(image, base, digest)
        if tag == "PWV3"
        else {"available": False, "reason": "extended annotations are PWV3-specific"}
    )
    sample = inspect_anlz_pwv3(anlz_path) if anlz_path is not None else None
    control_tags = ("PWV3", "PWAV", "PWV2", "PWV4", "PWV5")
    tag_presence = {
        control: [_hex(address) for address in find_tag_occurrences(image, base, control.encode("ascii"))]
        for control in control_tags
    }

    trace = {
        "schema": 1,
        "input": {
            "path": str(image_path.resolve()),
            "sha256": digest,
            "length": len(image),
            "base": _hex(base),
            "endianness": "little",
            "architecture": "SH-4A (objdump decoder: sh4)",
        },
        "tag": tag,
        "tag_occurrences": [_hex(address) for address in occurrences],
        "tag_presence_controls": tag_presence,
        "known_lookup_sites": lookup_details,
        "functions": [_serialise_dataclass(item) for item in functions],
        "comparisons_by_function": comparisons,
        "caller_xrefs": {
            "direct_bsr": [_serialise_dataclass(item) for item in direct_callers],
            "literal_jsr": [_serialise_dataclass(item) for item in indirect_callers],
            "pointer_tables": [_serialise_dataclass(item) for item in pointer_tables],
        },
        "canonical_anlz_sample": sample,
        "stock_v144_dataflow": stock_dataflow,
        "gnu_objdump": objdump_verification,
        "conclusions": {
            "verified": [
                "The listed lookup sites load a PWV3 tag pointer and compare four bytes.",
                "Stock v1.44 dispatches tag-table index 8 to a dedicated PWV3 metadata handler.",
                "The PWV3 handler stores a 24-byte descriptor and consumes entry_size * entry_count bytes without allocating or copying the payload during indexing.",
                "The post-index accessor at 0xA42AC380 seeks to saved_locator + len_header, allocates entry_size * entry_count bytes, and reads the PWV3 payload into that allocation.",
                "dbcl_GetParWaveData carries the allocated payload through public request 0x42E into a per-track object at +0x5A4.",
                "The detailed-waveform constructors copy raw PWV3 bytes into fixed 896-byte MAIN-to-GUI frames: 880 bytes in the first frame and up to 888 bytes in each extension frame.",
                "The legacy MAIN-side WAVE constructor consumes a staged 900-byte CWCASH record and emits message ID 4.",
                "The adjacent message-ID-5 constructor consumes a separate 103 x 36-byte CUEWAV table; its full staging-copy chain is proven and is not PWV3 payload flow.",
            ],
            "inferred": [
                "The three original containing functions are tag-list validators/classifiers, not payload handlers.",
                "The 0x426/0x427 request paths connect the CWCASH loader to the named dbcl_GetWaveData handlers through command routing.",
            ],
            "unresolved": [
                "The last generic-send step from the constructed detailed-waveform shared buffer to the physical MAIN-to-GUI SPORT/DMA link",
            ],
        },
    }
    return trace, disassemblies


def markdown_report(trace: dict) -> str:
    lines = [
        f"# {trace['tag']} static trace",
        "",
        "## Input",
        "",
        f"- Image: `{trace['input']['path']}`",
        f"- SHA-256: `{trace['input']['sha256']}`",
        f"- Base: `{trace['input']['base']}`; little-endian SH-4",
        f"- GNU objdump verified: `{trace['gnu_objdump'].get('verified', False)}`",
        "",
        "## Verified lookup sites",
        "",
        "| site | tag address | compare target | four-byte length | verified |",
        "|---|---|---|---:|---:|",
    ]
    for item in trace["known_lookup_sites"]:
        lines.append(
            f"| `{item['site']}` | `{item.get('tag_address')}` | "
            f"`{item.get('compare_target')}` | {item.get('length_is_four')} | "
            f"{item.get('verified')} |"
        )

    lines.extend(["", "## Tag presence controls", ""])
    for tag, addresses in trace["tag_presence_controls"].items():
        rendered = ", ".join(f"`{address}`" for address in addresses) or "absent"
        lines.append(f"- `{tag}`: {rendered}")

    lines.extend(["", "## Tag comparisons by containing function", ""])
    for function, comparisons in trace["comparisons_by_function"].items():
        tags = ", ".join(item["tag"] for item in comparisons) or "none recovered"
        lines.append(f"- `{function}`: {tags}")

    xrefs = trace["caller_xrefs"]
    lines.extend(
        [
            "",
            "## Caller recovery",
            "",
            f"- Direct BSR references: {len(xrefs['direct_bsr'])}",
            f"- Literal-resolved JSR references: {len(xrefs['literal_jsr'])}",
            f"- Raw pointer-table candidates: {len(xrefs['pointer_tables'])}",
            "",
            "A zero count is a verified negative for the implemented reference form, not proof that the function is unreachable. Relative dispatch tables and register-derived BSRF/JMP paths remain candidates.",
        ]
    )
    sample = trace.get("canonical_anlz_sample")
    if sample:
        lines.extend(
            [
                "",
                "## Canonical ANLZ sample",
                "",
                f"- PWV3 offset: `{sample['offset']}`; payload offset: `{sample['payload_offset']}`",
                f"- Header/tag length: {sample['header_length']} / {sample['tag_length']} bytes",
                f"- Entry size/count: {sample['entry_size']} × {sample['entry_count']} = {sample['payload_length']} payload bytes",
                f"- Size product matches payload: `{sample['size_product_matches_payload']}`",
            ]
        )

    flow = trace.get("stock_v144_dataflow", {})
    if flow.get("available"):
        dispatch = flow["tag_index_dispatch"]
        handler = flow["pwv3_handler"]
        accessor = flow["pwv3_payload_accessor"]
        partial = flow["partial_wave_request_path"]
        detail = flow["detailed_wave_gui_boundary"]
        wave = flow["legacy_wave_gui_boundary"]
        cue = flow["cue_overlay_gui_boundary"]
        lines.extend(
            [
                "",
                "## Stock v1.44 PWV3 data flow",
                "",
                f"- Tag table `{dispatch['pointer_table']}` → classifier `{dispatch['classifier']}` → call `{dispatch['classifier_call']}` → index {dispatch['pwv3_index']} branch `{dispatch['pwv3_branch']}`.",
                f"- Handler `{handler['range']['start']}`–`{handler['range']['end']}` stores a {handler['owner_descriptor']['size']}-byte descriptor at owner+`{handler['owner_descriptor']['offset']}`.",
                f"- Payload handling: {handler['payload_action']}; {handler['allocation_or_copy']}.",
                f"- Post-index accessor `{accessor['address']}` seeks to {accessor['payload_address_expression']}, allocates {accessor['payload_byte_count_expression']} bytes, and reads the payload into result+16.",
                f"- `{partial['named_api']}` `{partial['named_api_address']}` carries that result through request `{partial['public_request']}`; GUI loader `{partial['gui_loader']}` stages it at track object+`{partial['track_payload_object_offset']}`.",
                f"- Detailed-waveform constructors `{detail['first_chunk_constructor']}` and `{detail['extension_constructor']}` copy {detail['outbound_representation']} into {detail['frame_size']}-byte frames at `{detail['message_buffer']}`.",
                f"- The first frame starts payload at +{detail['first_payload_offset']} and carries at most {detail['first_payload_maximum']} bytes; extensions start at +{detail['extension_payload_offset']} and carry at most {detail['extension_payload_maximum']} bytes. A {detail['trailer_size']}-byte computed trailer is written at +`{detail['trailer_offset']}`.",
                f"- After `dbcl_GetWaveData` `{flow['database_wave_path']['get_wave_data']}` succeeds, its callers copy {flow['database_wave_path']['result_copy_size']} bytes into a response at +{flow['database_wave_path']['result_destination_offset']}.",
                f"- The legacy WAVE path looks up a {wave['cache_payload_size']}-byte CWCASH record at `{wave['cache_lookup']}`, copies record+{wave['cache_payload_offset']} to `{wave['staging_buffer']}`, then calls `{wave['wave_builder']}` to create message ID {wave['message_id']}.",
                f"- The separate CUE path copies {cue['record_count']} x {cue['record_size']}-byte records through `{cue['working_table']}` → `{cue['canonical_table']}` → `{cue['gui_staging_buffer']}` before builder `{cue['cue_builder']}` creates message ID {cue['message_id']}.",
                "- The WAVE and CUE paths remain separate legacy controls; the partial/detail path above is the direct PWV3 consumer.",
                "",
                "### Remaining transport edge",
                "",
                detail["physical_transport_edge"] + ".",
                "",
            ]
        )
    lines.extend(["## Confidence-separated conclusions", ""])
    for category in ("verified", "inferred", "unresolved"):
        lines.append(f"### {category.title()}")
        lines.append("")
        lines.extend(f"- {item}" for item in trace["conclusions"][category])
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_trace_outputs(
    trace: dict, disassemblies: dict[str, str], output_directory: Path
) -> None:
    output_directory.mkdir(parents=True, exist_ok=True)
    (output_directory / "pwv3-trace.json").write_text(
        json.dumps(trace, indent=2) + "\n", encoding="utf-8"
    )
    (output_directory / "pwv3-trace.md").write_text(
        markdown_report(trace), encoding="utf-8"
    )
    for name, content in disassemblies.items():
        (output_directory / f"{name}.dis.txt").write_text(content, encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Trace an ANLZ tag through an SH-4 MAIN image without modifying it"
    )
    parser.add_argument("image", type=Path)
    parser.add_argument("--base", type=parse_int, default=DEFAULT_BASE)
    parser.add_argument("--tag", default="PWV3")
    parser.add_argument("--output", "-o", type=Path, required=True)
    parser.add_argument("--objdump", type=Path)
    parser.add_argument("--anlz", type=Path, help="optional real ANLZ/EXT positive control")
    parser.add_argument(
        "--lookup-site",
        action="append",
        type=parse_int,
        help="runtime lookup address; repeatable (defaults to known PWV3 sites)",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    sites = tuple(args.lookup_site) if args.lookup_site else KNOWN_PWV3_LOOKUPS
    try:
        trace, disassemblies = build_trace(
            args.image, args.base, args.tag, sites, args.objdump, args.anlz
        )
        write_trace_outputs(trace, disassemblies, args.output)
    except (OSError, UnicodeError, TraceError, subprocess.SubprocessError) as exc:
        print(f"error: {exc}")
        return 2
    print(f"wrote trace report to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
