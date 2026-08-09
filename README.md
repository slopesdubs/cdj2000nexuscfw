# cdj2000nxs-firmware

Reverse engineering of the Pioneer CDJ-2000NXS firmware update format.

**Start with [`docs/FINDINGS.md`](docs/FINDINGS.md)** — container format, LZSS
compression, both checksum layers, boot sequence, and the NXS-vs-NXS2 comparison.

## Status

**Solved and verified:** the `.UPD` container, the compression (algorithm read out of
the firmware's own decompressor rather than inferred), and both checksum layers —
CRC16-XMODEM per segment, plus a 16-bit byte sum on the MAIN payload. A functionally
identical firmware image has been rebuilt from parsed components, and the analysis has
been independently reproduced with GNU binutils `sh-elf`.

**Answered:** the CDJ-2000NXS cannot be given RGB colour waveforms by unlocking a
dormant feature — the supporting code does not exist. A controlled comparison against
the CDJ-2000NXS2 shows thirteen identical rekordbox analysis-tag entries and exactly two
differences: `PWV4` and `PWV5`. See FINDINGS §1.

**Solved to the waveform layer:** the complete stock PWV3 parser-to-GUI-renderer path
is mapped. An offline emulator reproduces the 896-byte frames, Blackfin reassembly,
12-byte column records, palette lookup, and RGB555 colour selected for every column.
Only the generic layer-to-DMA compositor and NXS2 GUI segment compression remain
unresolved; neither obscures the stock waveform colour seam.

**Offline PWV5 prototype complete:** a hash-gated builder now changes the parser
lookup, sends the full two-byte-per-column payload, converts PWV5 to height plus RGB555
in the stock waveform-record arena, and redirects the proven renderer load. The supplied real
EXT passes 68 CRC-valid frames and produces 29,804 colour columns. This is not yet safe
or approved for installation on hardware.

**Untested:** everything, on hardware.

## No firmware in this repo

Pioneer/AlphaTheta firmware is copyrighted and is **not** committed here — see
`.gitignore`. Rebuilt and patched images are derivative works and are likewise not
redistributed.

Supply your own stock `C2KNXS.UPD` (v1.44) from the official AlphaTheta support site.
Every tool here operates on your local copy, and the rebuild is reproducible: running
`upd_build.py` against stock regenerates the same output.

Also excluded: service manuals, device dumps, and anything unit-specific.

## Layout

```
docs/
  FINDINGS.md              main reference - read first
  LAB.md                   offline firmware/ANLZ inspection and waveform rendering
  TOOLCHAIN.md             building the SH-4 cross-compiler
  DECISIONS.md             append-only decisions log
  ARCHIVE-working-notes.md superseded running notes, kept for history
tools/
  srec_parse.py            Motorola S-record parser
  lzss_codec.py            LZSS compressor + decompressor (matches firmware exactly)
  upd_build.py             S-record generation, CRC16-XMODEM, .UPD assembly
  upd_container.py         strict .UPD parser, CRC validation, MAIN extraction
  anlz_color.py            PWV4/PWV5 parser + dependency-free PNG renderer
  cdj_lab.py               command-line entry point for the offline lab
  sh4_trace.py             read-only SH-4 tag/xref/data-flow report generator
  nxs_wave_emulator.py     stock detailed-waveform frame encoder/reassembler
  nxs_color_patch.py       hash-gated offline PWV5 MAIN+GUI candidate builder
  ethernet_trace.py        read-only PCAP/PCAPNG waveform correlation scanner
  sh4dis.py                SH-4 disassembler (little-endian)
  bfindis.py               Blackfin disassembler (GUI processor)
  dataflow.py              Blackfin constant/pointer propagation
  harness.py               GUI image loader + dataflow queries
scripts/
  build-sh4-binutils.sh    pinned project-local GNU SH-4 binutils build
```

`srec_parse` → `lzss_codec` → `upd_build` are the three that matter for rebuilding
firmware. The rest are analysis only.

> `docs/ARCHIVE-working-notes.md` is a running log containing claims later corrected.
> **Do not cite it.** `FINDINGS.md` supersedes it throughout.

## Quick start

```bash
python3 --version          # 3.8+; no dependencies needed
# place your own stock C2KNXS.UPD in the working directory
```

Run the synthetic test suite and see the offline lab guide:

```bash
python3 -m unittest discover -s tests -v
python3 tools/cdj_lab.py --help
```

See [`docs/LAB.md`](docs/LAB.md) for firmware inspection and `PWV4`/`PWV5`
rendering commands. Real firmware and rekordbox analysis samples belong under the
ignored `work/` directory.

Reproduce the targeted stock-v1.44 trace:

```bash
./scripts/build-sh4-binutils.sh
python3 tools/cdj_lab.py trace-main \
  work/unpacked/nxs-stock/MAIN_decomp.bin \
  --objdump work/toolchain/sh-elf/bin/sh-elf-objdump \
  --anlz work/samples/ANLZ0000.EXT \
  --output work/analysis/pwv3
```

Emulate the stock detailed-waveform frame boundary with a real rekordbox EXT:

```bash
python3 tools/cdj_lab.py emulate-waveform work/samples/ANLZ0000.EXT \
  --output work/analysis/nxs-wave-emulator
```

Reproduce the stock Blackfin GUI receiver trace:

```bash
./scripts/build-bfin-binutils.sh
python3 tools/cdj_lab.py trace-gui \
  work/unpacked/nxs-stock/GUI.segment \
  --objdump work/toolchain/bfin-elf/bin/bfin-elf-objdump \
  --output work/analysis/gui-receiver
```

Extract the MAIN processor image:

```python
import sys; sys.path.insert(0, 'tools')
from srec_parse import parse_srec

d = open('C2KNXS.UPD','rb').read()
sizes = [2015268, 388690, 7062204, 98888]      # GUI, DRIV, MAIN, PANL
off = 33; segs = []
for L in sizes:
    segs.append(d[off:off+L]); off += L

_, chunks, _ = parse_srec(segs[2])
mx = max(a+len(x) for a,x in chunks)
img = bytearray(b'\xff'*mx)
for a,x in chunks: img[a:a+len(x)] = x
open('MAIN.bin','wb').write(bytes(img))
```

Decompress the payload:

```python
import struct, sys; sys.path.insert(0,'tools')
import lzss_codec as L

img = open('MAIN.bin','rb').read()
clen = struct.unpack_from('<I', img, 0x40000)[0]
open('MAIN_decomp.bin','wb').write(L.decompress(img, 0x40004, clen))
```

Verify against the firmware's own checksum:

```python
stored = img[0x40004+clen] | (img[0x40004+clen+1] << 8)
calc   = sum(img[0x40000:0x40004+clen]) & 0xFFFF
assert stored == calc      # 0xF05D on stock v1.44
```

## Hardware procedures

Hold while powering on, until the Pioneer logo clears:

| mode | buttons |
|---|---|
| Service mode | TEMPO + MEMORY |
| Update / recovery (USB) | MEDIA SELECT/USB + RELOOP |
| PANEL recovery | USB-STOP only |

MAIN, GUI and PANEL each have a documented emergency recovery path if a flash fails.
**DRIVE does not** — never include a DRIVE segment in a test image. USB media must be
FAT or FAT32.

Keep untouched stock v1.44 on a USB stick at all times as the way back.

## Working agreement

- Branch per piece of work, PR into `main`, other person reviews before merge.
- Anything learned from hardware goes in `docs/FINDINGS.md` in the same PR.
- Decisions that shape direction get an entry in `docs/DECISIONS.md`.
- Flag confidence explicitly: **verified** (reproduced or checksum-proven),
  **inferred** (reasoned but untested), **speculative**. Several early conclusions in
  this project were wrong in ways that looked right; labelling saves re-deriving them.
- Never commit firmware, service manuals, device serials, or MAC addresses.

## Next steps

1. On a sacrificial deck, prove official-stock update, local rebuild, and recovery.
2. Inject a chained no-op GUI routine and confirm boot/load behavior before enabling
   any PWV5 hooks.
3. Measure the 68-frame transfer and stress track load, zoom, seek, and unload while
   watching the GUI receiver-buffer lifetime.
4. Generalise the canonical 29,804-column guard and add a legacy fallback for tracks
   without PWV5.
5. Compare the NXS2 PWV5 receiver as a positive control when its GUI compression is
   available.

## Licence

Tools and documentation: choose one (MIT or GPL-3.0) before making the repo public.
No Pioneer/AlphaTheta material is included or redistributed. Pioneer DJ, AlphaTheta and
CDJ are trademarks of their respective owners. This is independent, unsupported
research with no affiliation to the manufacturer.
