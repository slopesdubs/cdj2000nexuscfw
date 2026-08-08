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

The detailed-waveform receive path is now mapped through its first display-oriented
consumer. Final pixel drawing remains unresolved.

- **Framebuffer at `0x00659B88`**, read directly from a live DMA descriptor at
  `0x00CC4EAC` (not inferred). Fed by DMA0 → PPI in a self-relinking loop; 480 px wide,
  16-bit colour.
- **A palette/graphics API is present** — debug strings for `DS_GR_SetPaletteColor`,
  `DS_GR_CreatePalette`, `DS_GR_SetWindowPalette`, `DS_GR_SetLayerColor` etc. at
  `~0x00C6A7F8`–`0x00C6AEFC`. **Nothing references those addresses** anywhere in the
  ~915 KB of decoded code — not as computed constants, not as pointer-table entries.
  They are almost certainly linker/debug residue; any real dispatch is indirect.
- **SPORT1/DMA ownership is verified.** `0x00D0C548` sets `TCR2`/`RCR2 = 0x020F`,
  `TCR1 = 0x2602`, and `RCR1 = 0x6400`. Routine `0x00D0C59A` writes its buffer and
  word-count arguments to DMA3 `START_ADDR`/`X_COUNT` (`0xFFC00CC4`/`0xFFC00CD0`),
  uses a two-byte modify, and enables SPORT1 RX. DMA4 at `0x00D0C66C` owns transmit.
- **A window/layer struct at `0x00658C74`** — two pointers, two byte flags, a 16-bit
  counter — with a framebuffer-adjacent pointer written into it at `0x00CFC6D2`.
- A GPIO interrupt priority-encoder at `~0x00D0C1D0` (reads `FIO_FLAG_D`, clears via
  `FIO_FLAG_C`).

### Detailed-waveform GUI receiver

Baseline: stock v1.44 GUI segment, SHA-256
`94a64347…f906bd2`, decoded as little-endian Blackfin with GNU binutils 2.45.1.

**Verified receive path:** initialization and every normal reset arm DMA3 for 32 words
(64 bytes) at `0x01F00000`. The transport state machine then receives the 896-byte
message at `0x01F00040`. Routine `0x00D10858` computes CRC16-XMODEM over its first
894 bytes and compares the word at inner offset `+894`; at `0x00D108D2` it reads the
inner word at `+0`. Values `6`, `3`, `32`, and `33` have distinct handlers. Value `32`
branches directly to `0x00D0FA64` — the stock detailed-waveform receiver.

Its reads and copies exactly confirm the MAIN-side frame map:

| inner field | first frame | continuation |
|---|---:|---:|
| command | word `+0` = 32 | word `+0` = 32 |
| sequence | little-endian `u32 +2` | little-endian `u32 +2` |
| total PWV3 bytes | little-endian `u32 +6` | absent/data begins here |
| opaque values | words `+10`, `+12` | absent |
| copied data | `+14`, 880 bytes | `+6`, 888 bytes |

The first frame must have sequence 1. Receiver state stores total bytes at
`0x006D413C`, write offset at `0x006D4140`, and expected sequence at `0x006D414A`.
Copies go to fixed buffer `0x01A65168`. Continuations increment and compare the
sequence before appending. Completion invokes the command event path; event dispatcher
`0x00D0F36C` recognizes value 32, handler `0x00D0F4F4` loads the retained total, and
calls the first display consumer at `0x00D2F51C`.

**Verified first consumer:** `0x00D2F51C` reads bytes from `0x01A65168` and produces
12-byte records beginning at `0x01011940`. For each input byte `b`, it writes:

```text
record word +0 = (((b & 0xE0) >> 5) << 8) | (b & 0x1F)
record byte +2 = 0
record stride   = 12 bytes
```

This proves the GUI receives raw PWV3 and separates its five-bit height from the
existing three-bit legacy colour code. It does **not** decode RGB: PWV5 has three
independent RGB components and twice the bytes per column, while this loop advances
one byte per record. The live conversion count is clamped through runtime display
state before the loop, so the exhaustive offline record image is a model rather than
a claim that every record is always converted in one call.

**Verified renderer:** height accessor `0x00D2E17C` and colour accessor `0x00D2E1E8`
feed column renderer `0x00D2E230`, called at `0x00D2F3B6` and `0x00D2F3D8`. The
renderer uses the three-bit colour code as an index into eight four-byte entries at
`0x00CD3928`, then loads the low 16-bit palette word:

```text
index:   0      1      2      3      4      5      6      7
RGB555: 0993   0A17   065F   0AFD   3F1C   4B1F   4B1F   6BBF
```

Routine `0x00D2C052` independently proves the pixel format by packing 8-bit channels
as `((R >> 3) << 10) | ((G >> 3) << 5) | (B >> 3)`: **RGB555**, not RGB565.
Renderer writes begin at `0x01008980`, row 44 of a 400×90, 16-bit off-screen surface
at `0x01000000`; its row stride is 800 bytes and each column extends upward by at most
31 pixels. Surface setup `0x00D2F418` registers that 72,000-byte layer through
`0x00D02600` and activates it through `0x00D02A48`.

This closes the waveform-specific chain:

```text
raw PWV3 -> 12-byte record -> height + 3-bit palette index
         -> palette word -> RGB555 waveform-layer pixels
```

The remaining unresolved edge is generic graphics plumbing from the registered layer
at `0x01000000` to DMA0 scanout storage at `0x00659B88`. It is no longer a blocker for
designing the colour-waveform data path. The limiting fact is now concrete: the stock
record and renderer carry one of eight palette indices, whereas PWV5 needs three
independent colour components. A parallel RGB555-per-column buffer is the least
invasive first design to test; widening the 12-byte record would affect more consumers.

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

**The post-index edge is now proven.** Accessor `0xA42AC380` reads the saved locator
from `owner+0x12C0` and descriptor fields at `owner+0x12CC`, `+0x12D6`, `+0x12D8`,
and `+0x12DC`. It seeks to `locator + len_header`, allocates
`entry_size × entry_count` bytes via `0xA4219B3C`, clears the allocation, and reads
the payload through `0xA42194FE`. Its 20-byte result contains entry count, entry size,
byte count, the descriptor's unknown word, and the allocated payload pointer at `+16`.
The direct call is `0xA418285C` in wrapper `0xA4182800`.

Firmware strings identify the next layer as `dbcl_GetParWaveData` at `0xA414ADBC`.
It uses database request/response IDs `0x2904`/`0x4A02`. Service handler
`0xA417234E` exposes the result through public request `0x42E`, placing the payload
pointer and count at response offsets `+44` and `+48`. GUI loader `0xA4335EF6`
issues request `0x42E`, validates response `0x13B5`, and stores those values in
`0x0556D9F8`/`0x0556D9FC`. Stager `0xA433702E` then transfers them to the current
track object at `+0x5A4`/`+0x5A8`, freeing a replaced allocation and setting its ready
flag.

**Verified detailed-waveform MAIN→GUI construction:** Shift-JIS debug strings name
the code “GU send: detailed waveform.” Header constructor `0xA425B8E0` reads the
per-track object at `+0x5A4`. First-chunk constructor `0xA425BD60` and extension
constructor `0xA425C0CC` dereference result `+16` and copy the **raw PWV3 bytes** into
shared buffer `0x04985564`; there is no height or pixel transformation in these loops.

| frame field | first frame | extension frame |
|---|---:|---:|
| word at `+0` | `32` | `32` |
| payload offset | `+14` | `+6` |
| maximum PWV3 bytes | 880 | 888 |
| computed 16-bit trailer | `+0x37E` | `+0x37E` |
| total frame size | 896 | 896 |

The trailer is computed by `0xA4310FC0`. Direct reconstruction of its shift/XOR loop
proves it is CRC16-XMODEM (polynomial `0x1021`, initial value zero) over the first 894
bytes, stored little-endian. Sequence/count words are maintained at `+2`/`+4`, and the
extension path subtracts 888 bytes from the remaining count per frame. The reusable
buffer is not cleared between extensions, so unused bytes in the final short frame
retain the previous frame's tail and are included in its CRC.

`tools/nxs_wave_emulator.py` reproduces this behavior. Applied to the supplied EXT, it
turns the 29,804 PWV3 bytes into 34 fixed frames, validates every CRC, and reassembles
the source payload byte-identically. The same harness can place 59,608 raw PWV5 bytes
in 68 frames as an explicitly experimental envelope test; this does not imply that the
stock GUI can decode or render them.

This supplies direct data-flow proof from the retained PWV3 locator to an outbound
detailed-waveform buffer. The matching Blackfin receiver in §6 independently confirms
the frame fields, CRC boundary, chunk offsets, sequence handling, and raw-PWV3 payload.
The exact SH-4 generic-send routine remains unnamed, but the two ends now prove what
crosses the SPORT/DMA link and where it is consumed.

The later database path is anchored by firmware debug names. `dbcl_GetWaveData`
(`0xA4149632`) is called at `0xA41721EE` and `0xA41722D2`; after a successful return,
its callers copy 900 bytes to response offset `+112`. Disc and SD/USB registration
functions are `0xA414984A` and `0xA414978A`.

**Corrected MAIN-side GUI split:** the 900-byte WAVE constructor is `0xA4260C82`, not
`0xA4260D94`. The operation at `0xA426017E` calls cache lookup `0xA4336DDC`; a hit
returns one of 20 `_CWCASH_` records at `0x05560698` with stride `0x8B0`. At
`0xA4260378`, 900 bytes are copied from record offset `+40` into staging buffer
`0x04985D64`; call `0xA42603B2` then invokes `0xA4260C82`. The constructor emits
message ID 4 in `0x049854F4`, transforms the source's 800-byte and 100-byte regions
into 16-bit fields, and is directly labelled `WAVE[%d,%d]` by a firmware debug string.
The command-routing link between this cache loader and `dbcl_GetWaveData` remains
inferred; the addresses, sizes, cache layout, copy, and GUI construction are verified.

**Verified separate CUE overlay path:** `0xA4336070` copies an exact `0xE7C`-byte
response payload from offset `+112` into `0x0556C858`. Call `0xA4334FE0` copies that
working table to canonical table `0x0556B458` and sets ready flag `0x0556C2D4`.
Initializer `0xA4336AAE` proves the table is exactly 103 records of 36 bytes. At
`0xA426087A` the entire table is snapshotted to `0x049860F0`, and call `0xA42608B8`
invokes builder `0xA4260D94`. That builder processes at most 100 cue records and emits
message ID 5. `_CUEWAV_` and CUE-operation debug strings prove these are cue/marker
records, not PWV3 waveform samples.

The legacy 900-byte WAVE/CWCASH and 103-record CUE overlay paths remain useful
boundary controls, but they are independent of this now-proven PWV3 partial/detail
waveform path. In particular, the 36-byte cue records are not waveform samples.

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
