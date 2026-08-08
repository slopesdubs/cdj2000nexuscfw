"""Shared harness: load NXS GUI LDR image, decode ranges, run dataflow queries."""
import struct
import sys
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parent
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from bfindis import decode
import dataflow
from upd_container import parse_upd

ZEROFILL = 0x0001
FINAL = 0x8000


def load_gui(path=None):
    """Load the GUI segment from an NXS update file.

    ``path`` is explicit by design; the current directory fallback is retained for
    interactive compatibility with the original analysis notebooks.
    """
    update_path = Path(path) if path is not None else Path.cwd() / 'C2KNXS.UPD'
    return parse_upd(update_path.read_bytes()).segments['GUI']


def parse_ranges(gui):
    n = len(gui)
    pos = 0x20
    ranges = []
    mem = {}
    count = 0
    while pos + 10 <= n:
        addr, cnt, flags = struct.unpack_from('<IIH', gui, pos)
        pos += 10
        if flags & ZEROFILL:
            mem[addr] = b'\x00' * cnt
        else:
            ranges.append((pos, pos + cnt, addr))
            mem[addr] = gui[pos:pos + cnt]
            pos += cnt
        count += 1
        if flags & FINAL:
            break
        if count > 200000 or cnt > 0x400000:
            break
    return ranges, mem


def decode_range(gui, fs, fe, base_addr):
    chunk = gui[fs:fe]
    a = base_addr
    i = 0
    L = len(chunk)
    insns = []
    while i + 2 <= L:
        w0 = chunk[i] | (chunk[i + 1] << 8)
        if (w0 & 0xc000) == 0xc000 and i + 4 <= L:
            w1 = chunk[i + 2] | (chunk[i + 3] << 8)
            ins = decode(a, w0, w1)
            step = 4
        else:
            ins = decode(a, w0)
            step = 2
        insns.append(ins)
        a += step
        i += step
    return insns


def find_accesses(lo, hi, progress=False, path=None):
    """Return every dataflow-resolved access landing in [lo,hi)."""
    gui = load_gui(path)
    ranges, mem = parse_ranges(gui)
    results = []
    for idx, (fs, fe, base_addr) in enumerate(ranges):
        insns = decode_range(gui, fs, fe, base_addr)
        funcs = dataflow.find_functions(insns)
        for start, fins in funcs:
            for acc in dataflow.analyse(fins):
                if lo <= acc.target < hi:
                    results.append((start, acc))
        if progress and idx % 50 == 0:
            print(f"  ...range {idx}/{len(ranges)}", file=sys.stderr)
    return results
