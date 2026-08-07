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

**Not solved:** the MAIN↔GUI protocol, the GUI waveform renderer, the NXS2's GUI
segment compression.

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
  TOOLCHAIN.md             building the SH-4 cross-compiler
  DECISIONS.md             append-only decisions log
  ARCHIVE-working-notes.md superseded running notes, kept for history
tools/
  srec_parse.py            Motorola S-record parser
  lzss_codec.py            LZSS compressor + decompressor (matches firmware exactly)
  upd_build.py             S-record generation, CRC16-XMODEM, .UPD assembly
  sh4dis.py                SH-4 disassembler (little-endian)
  bfindis.py               Blackfin disassembler (GUI processor)
  dataflow.py              Blackfin constant/pointer propagation
  harness.py               GUI image loader + dataflow queries
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

1. Official stock update on a sacrificial unit — proves procedure and media.
2. Flash the v1.45 rebuild. **Pass = deck displays 1.45.**
3. Prove recovery: return to stock, confirm it takes.
4. Inject code into free space (~331 KB of `0xFF` padding; largest blocks at
   `0xA40D57C4` and `0xA43C55F8`). Pass = deck still boots. Needs the SH-4 toolchain.
5. Decode the MAIN↔GUI protocol; locate the GUI waveform renderer. Needs hardware
   instrumentation — or possibly the serial debug console described in FINDINGS §8c.

## Licence

Tools and documentation: choose one (MIT or GPL-3.0) before making the repo public.
No Pioneer/AlphaTheta material is included or redistributed. Pioneer DJ, AlphaTheta and
CDJ are trademarks of their respective owners. This is independent, unsupported
research with no affiliation to the manufacturer.
