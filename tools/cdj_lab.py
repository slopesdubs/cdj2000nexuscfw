#!/usr/bin/env python3
"""Command-line entry point for the offline CDJ-2000NXS firmware lab."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from anlz_color import (
    AnlzError,
    parse_anlz,
    parse_pwv3,
    parse_pwv4,
    parse_pwv5,
    render_anlz_file,
)
from gui_receiver_trace import (
    GuiTraceError,
    build_gui_receiver_trace,
    write_gui_receiver_trace,
)
from nxs_wave_emulator import WaveEmulatorError, emulate_anlz_file
from sh4_trace import DEFAULT_BASE, build_trace, parse_int, write_trace_outputs
from upd_container import (
    SEGMENT_NAMES,
    UpdError,
    find_main_payload,
    parse_upd,
    parse_single_segment_upd,
    segment_ascii_header,
    srec_flat_image,
    verify_segment_crc,
)


def load_update(path: Path):
    data = path.read_bytes()
    try:
        return parse_upd(data)
    except UpdError as four_segment_error:
        try:
            return parse_single_segment_upd(data)
        except UpdError:
            raise four_segment_error


def inspect_upd(path: Path) -> int:
    update = load_update(path)
    print(f"file: {path}")
    print(f"container header: {update.header_size} bytes")
    crc_failed = False
    names = tuple(name for name in SEGMENT_NAMES if name in update.segments)
    for name in names:
        segment = update.segments[name]
        result = verify_segment_crc(name, segment)
        state = "OK" if result.valid else "FAIL"
        crc_failed = crc_failed or not result.valid
        padding = (
            f", pre-CRC field={result.padding_bytes} bytes"
            if result.padding_bytes
            else ""
        )
        print(
            f"{name:4}: {len(segment):9} bytes  CRC={state} "
            f"stored=0x{result.stored:04X} calculated=0x{result.calculated:04X} "
            f"({result.byte_order}-endian{padding})"
        )
        print(f"      header={segment_ascii_header(segment)!r}")

    main_image, entries = srec_flat_image(update.segments["MAIN"])
    print(f"MAIN flat image: {len(main_image)} bytes (0x{len(main_image):X})")
    print(
        "MAIN entries:",
        ", ".join(f"S{kind}=0x{address:X}" for kind, address in entries),
    )
    payload = find_main_payload(main_image)
    print(
        f"MAIN payload: offset=0x{payload.offset:X}, compressed={payload.compressed_length}, "
        f"decompressed={len(payload.decompressed)}, checksum=OK (0x{payload.stored_checksum:04X})"
    )
    return 1 if crc_failed else 0


def unpack_upd(path: Path, output: Path) -> int:
    update = load_update(path)
    names = tuple(name for name in SEGMENT_NAMES if name in update.segments)
    failures = [
        name
        for name in names
        if not verify_segment_crc(name, update.segments[name]).valid
    ]
    if failures:
        raise UpdError(f"refusing to unpack: invalid segment CRC ({', '.join(failures)})")
    output.mkdir(parents=True, exist_ok=True)
    for name in names:
        (output / f"{name}.segment").write_bytes(update.segments[name])
    main_image, _ = srec_flat_image(update.segments["MAIN"])
    (output / "MAIN.bin").write_bytes(main_image)
    payload = find_main_payload(main_image)
    (output / "MAIN_decomp.bin").write_bytes(payload.decompressed)
    print(f"wrote four segments, MAIN.bin, and MAIN_decomp.bin to {output}")
    return 0


def inspect_anlz(path: Path) -> int:
    anlz = parse_anlz(path.read_bytes())
    print(f"file: {path}")
    print(
        f"PMAI: header={anlz.header_length}, file={anlz.file_length}, "
        f"tags={len(anlz.tags)}"
    )
    for tag in anlz.tags:
        suffix = ""
        if tag.kind == "PWV3":
            unknown, columns = parse_pwv3(tag)
            suffix = f" columns={len(columns)} entry_bytes=1 unknown=0x{unknown:X}"
        elif tag.kind == "PWV4":
            unknown, columns = parse_pwv4(tag)
            suffix = f" columns={len(columns)} entry_bytes=6 unknown=0x{unknown:X}"
        elif tag.kind == "PWV5":
            unknown, columns = parse_pwv5(tag)
            suffix = f" columns={len(columns)} entry_bytes=2 unknown=0x{unknown:X}"
        print(
            f"0x{tag.offset:08X} {tag.kind} header={tag.header_length} "
            f"length={tag.tag_length}{suffix}"
        )

    pwv3 = anlz.find("PWV3")
    pwv5 = anlz.find("PWV5")
    if pwv3 and pwv5:
        _, blue = parse_pwv3(pwv3[0])
        _, color = parse_pwv5(pwv5[0])
        compared = min(len(blue), len(color))
        equal = sum(blue[i].height == color[i].height for i in range(compared))
        print(
            f"PWV3/PWV5 timeline: {len(blue)} / {len(color)} columns, "
            f"{compared / 150:.3f}s compared, exact-height matches={equal}/{compared}"
        )
    return 0


def render_anlz(args: argparse.Namespace) -> int:
    used = render_anlz_file(args.path, args.output, args.tag, args.width, args.height)
    print(f"rendered {used} to {args.output} ({args.width}x{args.height})")
    if used == "PWV4":
        print("PWV4 colour mapping is inferred; raw parsing and boundaries are verified.")
    return 0


def trace_main(args: argparse.Namespace) -> int:
    """Generate a confidence-separated, read-only ANLZ tag trace."""

    sites = tuple(args.lookup_site) if args.lookup_site else None
    keyword_args = {
        "image_path": args.path,
        "base": args.base,
        "tag": args.tag,
        "objdump_path": args.objdump,
        "anlz_path": args.anlz,
    }
    if sites is not None:
        keyword_args["lookup_sites"] = sites
    trace, disassemblies = build_trace(**keyword_args)
    write_trace_outputs(trace, disassemblies, args.output)
    print(f"wrote {args.tag} trace to {args.output}")
    return 0


def emulate_waveform(args: argparse.Namespace) -> int:
    manifest = emulate_anlz_file(
        args.path,
        args.output,
        args.tag,
        args.header_word_10,
        args.header_word_12,
    )
    source = manifest["source"]
    verification = manifest["verification"]
    print(
        f"emulated {source['tag']}: {source['payload_bytes']} payload bytes -> "
        f"{len(manifest['frames'])} x 896-byte frames"
    )
    print(
        f"CRC={'OK' if verification['all_crc_valid'] else 'FAIL'}, "
        f"round-trip={'byte-identical' if verification['byte_identical_round_trip'] else 'FAIL'}"
    )
    gui = manifest["gui_receiver"]
    print(
        f"GUI receiver={gui['first_consumer']}, "
        f"records={gui['column_transform']['converted_records']} x "
        f"{gui['column_transform']['record_stride']} bytes"
    )
    print(f"wrote frames and manifest to {args.output}")
    return 0


def trace_gui(args: argparse.Namespace) -> int:
    trace, disassemblies = build_gui_receiver_trace(args.path, args.objdump)
    write_gui_receiver_trace(trace, disassemblies, args.output)
    receiver = trace["receiver"]
    consumer = trace["consumer"]
    print(
        f"verified GUI command {receiver['message_word']} receiver "
        f"{receiver['handler']} -> {consumer['first_consumer']}"
    )
    print(f"wrote GUI receiver trace to {args.output}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline inspection and colour-waveform lab for CDJ-2000NXS firmware"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    upd = commands.add_parser("inspect-upd", help="validate and summarize a .UPD file")
    upd.add_argument("path", type=Path)
    upd.set_defaults(handler=lambda args: inspect_upd(args.path))

    unpack = commands.add_parser("unpack-upd", help="extract and decompress a .UPD file")
    unpack.add_argument("path", type=Path)
    unpack.add_argument("--output", "-o", type=Path, required=True)
    unpack.set_defaults(handler=lambda args: unpack_upd(args.path, args.output))

    anlz = commands.add_parser("inspect-anlz", help="list ANLZ tags and colour metadata")
    anlz.add_argument("path", type=Path)
    anlz.set_defaults(handler=lambda args: inspect_anlz(args.path))

    render = commands.add_parser("render-anlz", help="render PWV4/PWV5 to a PNG")
    render.add_argument("path", type=Path)
    render.add_argument("--output", "-o", type=Path, required=True)
    render.add_argument("--tag", choices=("auto", "PWV4", "PWV5"), default="auto")
    render.add_argument("--width", type=int, default=480)
    render.add_argument("--height", type=int, default=128)
    render.set_defaults(handler=render_anlz)

    trace = commands.add_parser(
        "trace-main", help="trace an ANLZ tag through a decompressed SH-4 MAIN image"
    )
    trace.add_argument("path", type=Path)
    trace.add_argument("--output", "-o", type=Path, required=True)
    trace.add_argument("--base", type=parse_int, default=DEFAULT_BASE)
    trace.add_argument("--tag", default="PWV3")
    trace.add_argument("--objdump", type=Path)
    trace.add_argument("--anlz", type=Path, help="optional real ANLZ/EXT positive control")
    trace.add_argument("--lookup-site", action="append", type=parse_int)
    trace.set_defaults(handler=trace_main)

    gui_trace = commands.add_parser(
        "trace-gui", help="trace the stock NXS Blackfin detailed-waveform receiver"
    )
    gui_trace.add_argument("path", type=Path, help="stock v1.44 GUI.segment or .UPD")
    gui_trace.add_argument("--output", "-o", type=Path, required=True)
    gui_trace.add_argument("--objdump", type=Path, required=True)
    gui_trace.set_defaults(handler=trace_gui)

    emulate = commands.add_parser(
        "emulate-waveform",
        help="emulate stock NXS detailed-waveform MAIN-to-GUI frames",
    )
    emulate.add_argument("path", type=Path, help="rekordbox ANLZ0000.EXT input")
    emulate.add_argument("--output", "-o", type=Path, required=True)
    emulate.add_argument("--tag", choices=("PWV3", "PWV5"), default="PWV3")
    emulate.add_argument(
        "--header-word-10",
        type=parse_int,
        default=0,
        help="opaque first-frame 16-bit word at offset 10 (default: 0)",
    )
    emulate.add_argument(
        "--header-word-12",
        type=parse_int,
        default=0,
        help="opaque first-frame 16-bit word at offset 12 (default: 0)",
    )
    emulate.set_defaults(handler=emulate_waveform)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.handler(args)
    except (
        OSError,
        UpdError,
        AnlzError,
        WaveEmulatorError,
        GuiTraceError,
        ValueError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
