# CDJ-2000NXS Firmware — Reverse Engineering Findings

**Subject:** Pioneer CDJ-2000NXS firmware v1.44 (`C2KNXS.UPD`), with CDJ-2000NXS2 v1.87
(`C2KNXS2.UPD`) as a comparison control.

**Original goal:** determine whether custom firmware could enable RGB colour waveform
display on the CDJ-2000NXS, as found on the CDJ-2000NXS2 and later.

**Outcome:** the question is answered — see §1. The firmware container, its compression,
and both of its checksum layers are fully documented and independently verified, and a
functionally-identical firmware image has been rebuilt from parsed components (§7).

This document supersedes all earlier drafts. Corrections made during the work are
folded in rather than listed as errata; §9 records only those mistakes that carry a
methodological lesson.

---

## 1. Conclusion

**The CDJ-2000NXS cannot be given RGB waveforms by patching or unlocking a dormant
feature. The supporting code does not exist in its firmware.**

The decisive evidence is a controlled comparison. Both the NXS and NXS2 MAIN firmwares
were decompressed by the same checksum-verified method and their rekordbox analysis-tag
support compared:

| tag | purpose | NXS | NXS2 |
|---|---|---|---|
| PMAI | ANLZ file header | 7 | 7 |
| PPTH | file path | 6 | 6 |
| PVBR | VBR index | 5 | 5 |
| PQTZ | beat grid | 5 | 5 |
| PWAV | waveform preview (blue, `.DAT`) | 6 | 6 |
| PWV2 | waveform preview tiny (`.DAT`) | 5 | 5 |
| PWV3 | scrolling waveform detail (blue, `.EXT`) | 3 | 3 |
| PCOB | cues / loops | 7 | 7 |
| PCO2 | extended cues (`.EXT`) | 4 | 4 |
| PKEY | key | 4 | 4 |
| PCPT | cue point | 5 | 5 |
| PCP2 | cue point v2 | 4 | 4 |
| PSSI | phrase / song structure | 0 | 0 |
| **PWV4** | **colour waveform preview (`.EXT`)** | **0** | **1** |
| **PWV5** | **colour waveform detail (`.EXT`)** | **0** | **1** |

Thirteen tags match exactly — same codebase, same parser, same analysis-file handling.
The only difference across the entire ANLZ tag surface is `PWV4` and `PWV5`.

In the NXS2 image those two appear in a dedicated table alongside the file extension:

```
PWV5 \0\0\0\0 EXT \0 PWV4
```

an explicit "colour waveform tags live in the `.EXT` file" association with no
counterpart anywhere in the NXS image.

**Mitigating finding:** the NXS *does* already locate, open and parse the `.EXT`
analysis file — `PWV3`, `PCO2` and `PKEY` are all `.EXT`-resident tags, and `EXT`
appears in its UTF-16 extension table. The file discovery and tag-walking
infrastructure for the file that *contains* the colour data is present and working.
What is absent is specifically: the two tag entries, their handlers, storage for the
colour data, transport of it to the GUI processor, and colour rendering there.

This is therefore a "build the feature" problem, not an "unlock the feature" problem.
§8 sets out what that would take.

---

## 2. Hardware

Four independent processors, each with its own firmware blob inside the single `.UPD`.
Identified from the official service manual's parts list and block diagram.

| segment | chip | part | role |
|---|---|---|---|
| `MAIN` | Renesas SH7764 (SH-4A) | R5S77641N300BG (IC10, MAIN Assy) | system control, USB, rekordbox DB / ANLZ parsing |
| `GUI`  | Analog Devices Blackfin | ADSP-BF531SBSTZ400 (IC4001, TFTA Assy) | LCD display control — draws the waveform |
| `DRIV` | Panasonic MN10300 family | MN103S71F (IC7006, SRVB Assy) | disc/servo mechanism |
| `PANL` | Renesas-family MCU | DYW1817 (IC8003, PNLB Assy) | buttons, LEDs, jog light |

`DRIV` and `PANL` are irrelevant to this investigation.

**MAIN is little-endian.** SH-4 endianness is a board configuration choice, and this
board wires it little-endian despite "SuperH" defaulting big-endian in most people's
expectations. Disassembling big-endian produces convincing-looking garbage. A prior
Ghidra session that stalled completely was almost certainly configured big-endian —
that single setting invalidates every function boundary, branch target and string
reference.

Note the CDJ-3000 / 3000X are a later hardware generation (ARM64 running Linux) and are
not comparable. Public CDJ-3000 modification work relies on a root exploit and runtime
library injection; none of that is applicable here, because the NXS is bare metal with
no OS, no filesystem, no runtime and no recovery mode.

---

## 3. `.UPD` container format

Fully verified by recomputation against both firmwares, and by byte-identical rebuild.

```
.UPD
  ASCII header : "<GUIlen>\r\n<DRIVlen>\r\n<MAINlen>\r\n<PANLlen>\r\n"
                 (33 bytes on NXS v1.44; 34 on NXS2 v1.87)
  GUI  segment  (GUIlen bytes)
  DRIV segment  (DRIVlen bytes)
  MAIN segment  (MAINlen bytes)
  PANL segment  (PANLlen bytes)
```

Each segment begins with a 32-byte ASCII header, e.g.
`"CDJ-2000NXS MAINVer1.44\x00       0"`.

### Segment trailer — CRC16-XMODEM

Polynomial `0x1021`, init `0x0000`, no input/output reflection, no final XOR.

**Byte order differs by segment type** — this is not uniform and is easy to get wrong:

| segment | coverage | stored as |
|---|---|---|
| GUI (Blackfin LDR) | `segment[:-4]` on NXS, `segment[:-2]` on NXS2 | **big-endian** |
| DRIV / MAIN / PANL (S-record) | `segment[:-2]` | **little-endian** |

The NXS GUI segment carries an extra 2-byte field (`0x0000`) between the body and the
CRC; NXS2's GUI does not. Check the last four bytes of any segment before assuming.

Verified values:

| segment | NXS | NXS2 |
|---|---|---|
| GUI  | `0x41ED` | `0x825C` |
| DRIV | `0xE9CE` | `0x7373` |
| MAIN | `0xD7A9` | `0x1AA3` |
| PANL | `0x138A` | `0x10F1` |

### S-record segments (DRIV / MAIN / PANL)

Standard Motorola S-records, CRLF-terminated:
- one `S0` header record (MAIN payload: `726F6D6F626A20206D6F74` = "romobj  mot")
- `S2` data records, 24-byte count field, **32 data bytes each**, ascending addresses
- one termination record — MAIN uses `S7` with entry `0xA0000000`; DRIV and PANL use
  `S8` with entry `0x0`

MAIN's address space has deliberate gaps (no records emitted): `0x60`–`0x100`,
`0x620`–`0x700`, `0xA20`–`0x10000`, `0x31820`–`0x40000`. Contiguous runs are therefore
`0x0`, `0x100`, `0x700`, `0x10000`, `0x40000`. The flat image spans `0x0`–`0x2E14C0`.

### GUI segment (Blackfin LDR)

Analog Devices boot-stream format. Block headers are 10 bytes, little-endian:
`addr` (u32), `count` (u32), `flags` (u16), followed by `count` body bytes — **except**
when `ZEROFILL` is set, in which case there is no body in the file and `count` zero
bytes should be written to `addr`.

Flags (taken from U-Boot's BF53x loader, not guessed):
`ZEROFILL 0x0001`, `RESVECT 0x0002`, `INIT 0x0008`, `IGNORE 0x0010`, `FINAL 0x8000`.

On the NXS the LDR blocks start at offset `0x20` and are **uncompressed** — the whole
~1.9 MB segment parses cleanly as ~995 blocks. **The NXS2's GUI segment is compressed**
(Analog Devices' documented "compressed streams" loader feature) and was not cracked;
this is the one remaining unknown in the container.

---

## 4. MAIN payload compression

Inside the MAIN flat image, at offset `0x40000` (NXS) / `0x50000` (NXS2):

```
u32  compressed length, little-endian
...  LZSS stream (length bytes)
u16  checksum, little-endian
```

The checksum is a plain **16-bit sum of all bytes over (the 4-byte length field + the
stream)**. Verified: NXS computes `0xF05D` and stores `0xF05D`; NXS2 computes `0x9499`
and stores `0x9499`. This match is independent confirmation that the format, the
boundaries and the algorithm are all correct.

### LZSS parameters

Read directly out of the decompressor at `0xA0000700` (§5), instruction by instruction —
not inferred statistically. It is textbook Okumura LZSS:

- ring buffer N = 4096, F = 18, THRESHOLD = 2
- ring pre-filled with `0x20` (space) for **4078** bytes (2039 iterations × 2)
- write pointer `r` starts at `N - F = 0xFEE = 4078`; mask `0xFFF`
- flags LSB-first, reloaded via the counter trick:
  `flags >>= 1; if !(flags & 0x100) { flags = *src++ | 0xFF00; }`
- **bit = 1 → literal** (one byte)
- **bit = 0 → match** (two bytes): `pos = lo | ((hi & 0xF0) << 4)`,
  `len = (hi & 0x0F) + 3`
- both paths write to `ring[r]` then `r = (r + 1) & 0xFFF`
- matches may overlap the write pointer (run-length behaviour is legal)

Decompressed sizes: NXS `0x3E0000` (4,063,232 bytes); NXS2 `0x573DD4` (5,717,460).
Load address `0xA4000000`.

An encoder written to these parameters round-trips the full 4 MB image byte-identically
and, tuned, produces output **315 bytes smaller** than Pioneer's own (§7).

---

## 5. MAIN boot sequence

Only ~2.3 KB of the 3 MB MAIN image is plain SH-4 code (`0x100`–`0x620` and
`0x700`–`0xA20`, ~92% decode validity). Everything else is compressed payload —
entropy 7.55–7.71 throughout, and the 32-bit value `0x00001000` appears **zero** times
in the whole image, which is impossible for ordinary firmware.

| address | function |
|---|---|
| `0xA0000000` | reset vector; stack setup, SR mask |
| `0xA0000100` | peripheral + SDRAM controller init |
| `0xA0000298` | RAM test (`0x55555555` / `0xAAAAAAAA` walk) |
| `0xA00004FC` | **DMA-accelerated memcpy** — programs SH7764 DMAC at `0xFF608060` (SAR +0x20, DAR +0x24, TCR +0x28, CHCR +0x2C), polls TE; falls back to a word loop under 16 bytes. Signature `(src, dst, len)` |
| `0xA0000700` | **LZSS decompressor** (§4). Signature `(src, dst, len)`; ring buffer at `0x0BFFD310` |
| `0xA00007CC` | byte-sum checksum helper |
| `0xA00008A6` | **orchestrator** — reads the length header, computes and verifies the payload checksum, then calls the decompressor `(src = payload+4, dst = 0xA4000000, len)`. Takes a raw-copy fallback path on checksum failure |

Boot order: init → memcpy `(0xA0040000 → 0xA7A00000, 0x3A0000)` moving the compressed
payload to RAM → memcpy `(0xA0000700 → 0xABFFD000, 0x1000)` relocating the decompressor
→ jump via the pointer at `0xA0000618` = `0x0BFFD1A6`, i.e. offset `0x1A6` into the
relocated block (`0xA00008A6` in-file).

---

## 6. GUI (Blackfin) findings

Less complete than MAIN — this processor was not fully mapped.

- **Framebuffer at `0x00659B88`**, read directly from a live DMA descriptor at
  `0x00CC4EAC` (not inferred). Fed by DMA0 → PPI in a self-relinking loop; 480 px wide,
  16-bit colour.
- **A palette/graphics API is present** — debug strings for `DS_GR_SetPaletteColor`,
  `DS_GR_CreatePalette`, `DS_GR_SetWindowPalette`, `DS_GR_SetLayerColor` etc. at
  `~0x00C6A7F8`–`0x00C6AEFC`. **Nothing references those addresses** anywhere in the
  ~915 KB of decoded code — not as computed constants, not as pointer-table entries.
  They are almost certainly linker/debug residue; any real dispatch is indirect.
- **SPORT1 is configured and its RX interrupt armed** (`0x00D0C548` sets
  `TCR2`/`RCR2 = 0x020F`, `TCR1 = 0x2602`, `RCR1 = 0x6400`; enable/disable pair at
  `0x00D0C5F2` / `0x00D0C61E`). DMA3 and DMA4 are configured nearby. This is the most
  likely MAIN↔GUI data link, but **the protocol was not decoded** and no consumer of
  received words was located.
- **A window/layer struct at `0x00658C74`** — two pointers, two byte flags, a 16-bit
  counter — with a framebuffer-adjacent pointer written into it at `0x00CFC6D2`.
- A GPIO interrupt priority-encoder at `~0x00D0C1D0` (reads `FIO_FLAG_D`, clears via
  `FIO_FLAG_C`).

**The waveform renderer itself was not found.** A dataflow scan of the entire graphics
SDRAM window resolved 81 accesses, all to global variables and none to the framebuffer —
which is expected and diagnostic: real drawing code computes pixel addresses
(`base + y*stride + x`) from pointers held in variables, so intra-function constant
tracking cannot reach them. Locating it needs inter-procedural analysis or, far more
cheaply, a hardware watchpoint on framebuffer memory.

---

## 6b. Real colour-analysis positive control

**Verified:** a user-supplied rekordbox `ANLZ0000.EXT` (SHA-256
`10de96c1…8c4d0`) parses cleanly as a 98,082-byte PMAI file with nine tags. The three
waveform tags are:

| tag | entries | bytes/entry | header value |
|---|---:|---:|---:|
| `PWV3` | 29,804 | 1 | `0x00960000` |
| `PWV5` | 29,804 | 2 | `0x00960305` |
| `PWV4` | 1,200 | 6 | `0x00000000` |

`PWV3` and `PWV5` therefore describe the exact same 198.693-second timeline at 150
columns per second. Their five-bit heights are identical in 18,639 of 29,804 columns
(62.5%); the remaining values differ in both directions. Colour detail is aligned with
the existing blue detail path but is not simply the same height with RGB bits attached.
All 29,804 `PWV5` entries have zero in their two reserved low bits, and every RGB
component spans the documented full range 0–7.

### Static PWV3 trace to the GUI boundary

Baseline: stock v1.44 decompressed MAIN, SHA-256
`f73da28a…b6301d4f`, loaded little-endian at `0xA4000000`. GNU binutils 2.45.1 from the
pinned KallistiOS `kos-chain` configuration is the authoritative decoder. Cached and
physical aliases are compared after masking to 29 address bits.

**Verified:** `0xA4388E5C` is a bounded four-byte comparison routine. All four original
sites load `PWV3` from `0xA40ACE60`, set the length to four, and call it:

| load site | literal pool | containing function |
|---|---|---|
| `0xA42ADE42` | `0xA42ADF88` | `0xA42ADC74`–`0xA42AE224` |
| `0xA42AE438` | `0xA42AE558` | `0xA42AE240`–`0xA42AEB8E` |
| `0xA42AE66E` | `0xA42AE840` | `0xA42AE240`–`0xA42AEB8E` |
| `0xA42AEE58` | `0xA42AF100` | `0xA42AEC10`–`0xA42AF172` |

Each function checks, in order, `PMAI`, `PPTH`, `PVBR`, `PQTZ`, `PWAV`, `PWV2`,
`PCOB`, `PWV3`, `PKEY`, `PCO2`, and `PCP2`; the middle function performs the chain
twice. Their callers are `0xA42AD594`, `0xA42AD780`, and `0xA42AD9EA`, reached through
wrappers `0xA4182C20`, `0xA4182CD2`, and `0xA4182D70` for request IDs `0x13E0`,
`0x13E1`, and `0x13E2`. **Inferred from arguments and exits:** these are validators or
classifiers, not payload constructors.

The real generic ANLZ path uses a 12-pointer table at `0xA40ACF6C`:

```text
PMAI PPTH PVBR PQTZ PWAV PWV2 PCOB PCPT PWV3 PKEY PCO2 PCP2
```

Classifier `0xA42B2F1A` returns the matching index. Its call at `0xA42BAD48` routes
index 8 to the dedicated `PWV3` handler at `0xA42BB650`–`0xA42BB7D6`.

**Verified storage map:** the handler zeroes and fills a 24-byte descriptor at
`owner+0x12C8`; the stream object pointer is at `owner+0x1DB4`.

| owner field | observed type | meaning | confidence |
|---:|---|---|---|
| `+0x12C0` | word/pointer-sized saved value | tag locator or stream/file position | inferred |
| `+0x12C8 + 0` | `char[4]` | tag | verified |
| `+0x12C8 + 4` | big-endian `u32` | `len_header` | verified |
| `+0x12C8 + 8` | big-endian `u32` | `len_tag` | verified |
| `+0x12C8 + 12` | big-endian `u16` | reserved/unknown | verified |
| `+0x12C8 + 14` | big-endian `u16` | entry size | verified |
| `+0x12C8 + 16` | big-endian `u32` | entry count | verified |
| `+0x12C8 + 20` | `u16` | unknown | verified |
| `+0x12C8 + 22` | `u16` | zeroed/unknown | verified |
| `+0x1DB4` | pointer | parser stream object | verified |

At `0xA42BB79A`, `entry_size × entry_count` is passed to `0xA42B3352`, which validates
or advances the stream. **No PWV3 payload allocation or copy occurs during this index
pass.** “Tag accepted” therefore means the descriptor and locator were retained, not
that 29,804 bytes were decoded into a resident waveform buffer. The supplied EXT is a
direct positive control: tag/payload offsets `0xCC`/`0xE4`, header 24,
tag length 29,828, entry size 1, entry count and payload length 29,804.

The later database path is anchored by firmware debug names. `dbcl_GetWaveData`
(`0xA4149632`) is called at `0xA41721EE` and `0xA41722D2`; after a successful return,
its callers copy 900 bytes to response offset `+112`. Disc and SD/USB registration functions are
`0xA414984A` and `0xA414978A`.

**Verified MAIN-side GUI message construction:** `0xA4260D94`, called at
`0xA42608B8`, constructs normal waveform message ID 5 in the buffer at `0x049854F4`.
The ID and record count are 16-bit fields at `+112` and `+114`; payload begins at
`+120`. It processes at most 100 source records with a 36-byte stride, calls
`0xA42A6EEA`, and emits transformed 16-bit words. Payload-byte and total-byte lengths
are written at `+28` and `+32`. This is not raw `PWV3`. The clear constructor at
`0xA42621CC` uses message ID 4; `0xA425C69A` is the current queue/copy candidate.

**Single unresolved edge:** direct pointer propagation has not yet been proved from
`owner+0x12C0`/the descriptor or the 900-byte `dbcl_GetWaveData` result into the
36-byte source records consumed by `0xA4260D94`. This one staging edge prevents a full
end-to-end proof; adjacent code is not being treated as evidence.

The trace is reproducible with `tools/sh4_trace.py` through the `trace-main` lab
command. It emits JSON, Markdown, and focused GNU disassemblies under ignored
`work/analysis/` and never modifies the image.

---

## 7. Verified rebuild

Both offline validation steps pass.

**Container round-trip.** The `.UPD` parses into header + four segments and reassembles
**byte-identical** (SHA-256 `b17c0f71…d81097` in and out). Separately, the entire MAIN
segment — all 90,540 S-records — was regenerated from the raw flat image and is
**byte-identical** to Pioneer's original, confirming the S-record generator, record
sizing, checksum bytes and record ordering.

**Codec round-trip.** A compressor written to the §4 parameters compresses the full
4,063,232-byte decompressed image and decompresses back **byte-identical**. At
`max_candidates=256` it produces 2,757,494 bytes against Pioneer's 2,757,809 — 315
bytes tighter, which is itself a strong indication the format is correctly understood.

**Rebuilt firmware.** `C2KNXS_rebuilt.UPD` was built end-to-end from parsed components,
with every byte of the compressed payload regenerated rather than copied:

| property | result |
|---|---|
| total file size | 9,565,083 — identical to stock |
| MAIN segment size | 7,062,204 — identical to stock |
| internal image size | `0x2E14C0` — identical to stock |
| all four segment CRCs | verify |
| MAIN payload checksum | verifies (`0x9D69`), computed as the boot ROM does |
| decompressed content | **identical to stock** |
| entry vector | `S7 0xA0000000` — unchanged |
| SHA-256 | `05c1398f…5db0f` — differs, as it must |

The payload region is padded to length with 324 bytes of `0xFF`, matching what stock
does in that region.

This is functionally identical firmware, rebuilt from parsed parts. It is the safest
possible test article: if a deck rejects *this*, the rejection is caused by something
unrelated to any future modification.

**It has never been tested on hardware.** "All checksums verify" means it satisfies
every check that was *found*, not every check that exists.

---

## 7b. The deck's updater — file table and per-processor updates

Recovered from the decompressed MAIN image at `~0x00D3C30`: the updater's own string
table, pairing each update filename with the segment header string it expects.

| filename | expected segment header | id |
|---|---|---|
| `C2KNXSG.UPD` | `CDJ-2000NXS GUI`  | 1 |
| `C2KNXSD.UPD` | `CDJ-2000NXS DRIV` | 4 |
| `C2KNXSM.UPD` | `CDJ-2000NXS MAIN` | 2 |
| `C2KNXSP.UPD` | `CDJ-2000NXS PANL` | 3 |
| `C2KNXS.UPD`  | `CDJ-2000NXS ALL`  | 5 |

Two consequences for testing:

**Per-processor updates exist.** `C2KNXSM.UPD` updates MAIN alone, leaving GUI, DRIV
and PANL untouched. Since all work here concerns MAIN, this is the lower-risk vehicle —
three of the four processors are never written.

**The segment ASCII header is matched against these exact strings**, so it must be
preserved byte-for-byte apart from the version field. Nearby strings (`Update_TASK`,
`Update_tmpl`, `CDJ ** Update ** END **`) belong to the same updater task.

**Version gating is a live risk.** A rebuilt image still declaring `Ver1.44` may be
skipped by a deck already on 1.44 — which would look like rejection but is not. Bumping
the version avoids the ambiguity; see the `v145` test article below.

## 7c. Test articles built

| file | purpose |
|---|---|
| `C2KNXS_rebuilt.UPD` | v1.44, content byte-identical to stock, payload fully regenerated. Tests the rebuild pipeline with zero functional change. |
| `C2KNXS_v145_test.UPD` | as above but version string changed to **1.45** in both the segment header and the internal display string. If the deck shows 1.45, the full decompress-edit-recompress-checksum-flash loop is proven. |
| `C2KNXSM_v145_MAINONLY.UPD` | the same MAIN segment alone, as a single-segment update file. **Header layout inferred, not verified** — the single-length header format is a reasonable reading of the container rule but has not been confirmed against a real per-processor file. Treat as experimental; prefer the full `.UPD` unless a genuine Pioneer per-processor file can be obtained for comparison. |

All three verify identically: four segment CRCs, payload checksum, unchanged image size
(`0x2E14C0`), unchanged entry vector, and correct decompression.

## 8. What building the feature would require

In dependency order:

1. **Prove the flash pipeline on hardware** — flash the rebuilt image, confirm normal
   boot and playback.
2. **Prove an observable edit** — change the version string (`1.44` is plain text in the
   decompressed image), rebuild, flash, confirm the deck's info screen reflects it. This
   closes the development loop and is the single most valuable milestone.
3. **Prove code execution** — place a small routine in free space, redirect something
   harmless to it, confirm the deck still boots. Requires an SH-4 cross-toolchain.
4. **Decode the MAIN→GUI protocol** — realistically a logic-analyser job on SPORT1.
5. **Locate the GUI waveform renderer** — the last unmapped subsystem.
6. **Implement:** `PWV4`/`PWV5` parser entries and handlers on SH-4; storage and a new
   message type carrying per-column colour; colour rendering on the Blackfin.

The display hardware is not a limitation — the panel is 16-bit colour and already draws
coloured artwork, cues and text. This is entirely a software gap.

Effort is realistically months, and steps 4–6 are impractical without hardware debug
access (JTAG on both processors, a logic analyser on the inter-board link, a flash
programmer, and a sacrificial deck).

**There is no recovery mode.** If the updater itself is broken by a bad flash, recovery
means a chip programmer and a soldering iron.

---

## 8b. Service mode, update mode, and recovery (from the service manual)

All of the following are **documented Pioneer procedures** requiring no firmware
modification. Verified against the CDJ-2000NXS service manual, section 6.1.

### Entry procedures

Hold the buttons while powering on, and keep holding until the Pioneer logo clears.

| mode | buttons |
|---|---|
| Service mode | **TEMPO + MEMORY** |
| Firmware update (USB) | **MEDIA SELECT/USB + RELOOP** |
| Firmware update (CD-R/RW) | **MEDIA SELECT/DISC + RELOOP** |
| PANEL recovery (special case) | **USB-STOP only** |

Service mode provides: button/jog/slider/encoder input test, jog load measurement,
version and error history display, error code list, drive self-diagnosis, drive
mechanism test, alarm port output, and firmware update.

### Update file names — confirmed

The manual confirms the per-processor filenames independently discovered in the
firmware's own string table (§7b):

| device | file | format |
|---|---|---|
| Main CPU | `C2KNXSM.UPD` | Motorola S-record text |
| GUI CPU | `C2KNXSG.UPD` | binary |
| Panel MCU | `C2KNXSP.UPD` | Motorola S-record text |
| Drive controller | `C2KNXSD.UPD` | Motorola S-record text |
| all four combined | `C2KNXS.UPD` | mixed |

Update order when using the combined file: **GUI -> DRIVE -> MAIN -> PANEL**. Devices
with no file present are greyed out and skipped. USB media must be **FAT or FAT32**
(HFS+ is explicitly unsupported).

### Recovery — MAIN is recoverable

> "When update of each CPU goes wrong and the power supply has been turned off on the
> way, subsequent normal operation becomes impossible. In this case, the recovery
> (emergency) mode which only updates operates."

| device | on failure | recoverable? |
|---|---|---|
| **MAIN** | error `E-7024: MAIN CPU ERROR` | **Yes** — re-enter update mode (USB + RELOOP) and retry. Only MAIN is written even if other files are present. |
| GUI | error `E-7023: GUI CPU ERROR` | Yes — same procedure |
| PANEL | error `E-7022: PANEL CPU ERROR` | Yes — but entry is **USB-STOP only** |
| DRIVE | error `E-7001: DISC DRIVE ERROR` | **No** — requires replacing IC7004 |

Recovery must use USB; CD-ROM cannot be used for recovery. If retrying still fails, the
flash chip itself may be defective (for MAIN this means replacing the whole MAIN Assy,
because the flash holds a unit-specific MAC address).

**Implication for this project:** all work targets MAIN, and MAIN has a documented
emergency recovery path. Using `C2KNXSM.UPD` writes MAIN alone and never touches DRIVE
(the one unrecoverable device). The realistic worst case for a bad MAIN image is an
error screen and a re-flash, not a dead unit. This is materially safer than assumed
earlier in the project — but it is a *documented* recovery, not a *tested* one, so a
sacrificial unit is still the right place to prove it.

## 8c. Other modification targets worth investigating

Identified from strings in the decompressed image. These are leads, not confirmed
findings — none has been traced to code.

**Serial debug console — strongest lead.** The firmware contains `232C Mode Change`,
`phy debug command (usage: phy <r|w|s|l>)`, `diag_ether <IPaddress> [I/F number]`,
`too many args`, and a full set of IP/ICMP packet-tracing controls. Usage strings with
argument syntax imply a command interpreter. If reachable (RS-232C appears to be the
route), this would give live introspection into the running firmware and could
substitute for much of the hardware instrumentation otherwise needed. Worth pursuing
before buying test equipment.

**Calibration parameters.** `TempoSliderMin` / `TempoSliderMax`,
`TouchBreakMin` / `TouchBreakMax`, `ReleaseStartMin` / `ReleaseStartMax`,
`JogPositionRev` / `JogPositionFwd` appear as named entries. Plausible targets for
altering tempo slider range or jog touch response.

**Cosmetic.** Version strings, UI text, error messages — trivially editable once the
edit-rebuild-flash loop is proven.

**Not a lead:** the `( 2000 only )` / `( 900 only )` annotations in the button-name
table reflect which physical controls exist on each model in a shared CDJ-2000/CDJ-900
codebase. They indicate hardware differences, not artificially gated features.

## 8d. Independent verification of this analysis

The findings in this document were independently confirmed using an unrelated toolchain
(GNU binutils 15.2.0 `sh-elf`, built via the KallistiOS builder — the Dreamcast is also
a little-endian SH-4).

```
sh-elf-objdump -D -b binary -m sh4 -EL --adjust-vma=0xA0000000 MAIN.bin
```

produces, at `0xA0000100`, the register-save prologue and delay loop described in §5;
at `0xA0000700`, the LZSS decompressor with every parameter in §4 visible as literal
instructions (`mov #32,r5` = space fill; `mov #16,r2 / shll8 / add #-18` = `0xFEE`;
`mov #16,r1 / shll8 / add #-1` = `0xFFF` mask; the `shlr` / `tst` / `or 0xFF00` flag
handling). Big-endian disassembly of the same bytes produces noise.

Two independently written disassemblers agreeing on the same bytes is strong
corroboration for the whole chain of analysis that follows from them.

## 9. Method notes worth carrying forward

Three mistakes here cost real time and each generalises:

**Compression masquerading as obfuscation.** The very first anomaly — an `ANLZ` string
with nothing referencing it — was the compression announcing itself, and it was
misread as a dead end for a long time. Several negative results obtained by searching
the *compressed* image were meaningless. Whenever strings exist but nothing points at
them, suspect packing before anything else.

**A negative result needs a positive control.** Searching for `PWV5` in the NXS returned
nothing — but the same search on the NXS2, which demonstrably has the feature, *also*
returned nothing. Without that control the right conclusion would have been reached for
entirely the wrong reason. The §1 comparison is only meaningful because both images are
checksum-verified decompressions.

**Byte order and field order are worth testing, never assuming.** MAIN is little-endian
despite SH-4's big-endian reputation. The compiler emits `.L` before `.H` when building
32-bit constants, and an early scanner that assumed the opposite paired the high half of
one address with the low half of the next — producing plausible, wrong answers because
neighbouring addresses share high halves. Segment CRCs are big-endian for GUI and
little-endian for the S-record segments. Every one of these was found by checking rather
than by reasoning from convention.

---

## 10. Tooling

Self-contained Python, no external dependencies:

| file | purpose |
|---|---|
| `srec_parse.py` | Motorola S-record parser |
| `sh4dis.py` | SH-4 disassembler (little-endian) |
| `bfindis.py` | Blackfin disassembler, built from binutils' `opcode/bfin.h` bit tables |
| `dataflow.py` | intra-function constant/pointer propagation for Blackfin; resolves load/store effective addresses through register moves, immediate arithmetic and FP-relative stack spills |
| `lzss_codec.py` | LZSS encoder + reference decoder matching the firmware exactly |
| `upd_build.py` | S-record generation, CRC16-XMODEM, `.UPD` assembly |
| `upd_container.py` | strict update-container, segment-CRC, S-record and MAIN-payload validation |
| `anlz_color.py` | strict PWV3/PWV4/PWV5 parsing and dependency-free PNG rendering |
| `sh4_trace.py` | SH-4 alias, call, literal, table and tag tracing with GNU verification |
| `ethernet_trace.py` | PCAP/PCAPNG waveform-evidence scanner and repeatability summary |
| `cdj_lab.py` | command-line entry point for firmware, ANLZ, rendering and trace workflows |
| `harness.py` | loads the GUI LDR image, decodes all ranges, runs dataflow queries |

## 11. References

- CDJ-2000NXS and CDJ-2000NXS2 service manuals — chip identification, block diagrams
- U-Boot, `common/cmd_bootldr.c` — BF53x LDR block flag definitions
- binutils/GDB, `include/opcode/bfin.h`, `opcodes/bfin-dis.c` — Blackfin instruction encoding
- Linux, `arch/blackfin/mach-bf533/include/mach/defBF532.h` — ADSP-BF531/532/533 register map
- Analog Devices *Blackfin Processor Programming Reference* rev 2.2
- Analog Devices *CrossCore Embedded Studio Loader and Utilities Manual* — LDR compressed streams
