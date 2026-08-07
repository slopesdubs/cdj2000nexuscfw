# CDJ-2000NXS RGB Waveform Mod — Reverse-Engineering Notes

**Goal:** Determine whether a custom firmware can be built for the Pioneer CDJ-2000NXS
to enable RGB color waveforms (a feature Pioneer restricts to the CDJ-2000NXS2/3000
line), by patching the stock firmware rather than writing new firmware from scratch.

**Status:** Active reverse engineering, no patch produced yet. This document is a
snapshot for handoff/second-opinion purposes, not a finished result.

---

## 1. Hardware architecture (confirmed from the official service manual)

The CDJ-2000NXS has **four separate CPUs**, each with its own firmware blob inside
the single `.UPD` update file:

| Segment | Chip | Part number | Role |
|---|---|---|---|
| `MAIN` | Renesas SH7764 (SH-4A core) | R5S77641N300BG (IC10, MAIN Assy) | System control, USB, rekordbox/ANLZ file parsing |
| `GUI`  | Analog Devices Blackfin | ADSP-BF531SBSTZ400 (IC4001, TFTA Assy) | **"LCD display control"** — this is the chip that actually draws the waveform |
| `DRIV` | Panasonic MN10300-family | MN103S71F (IC7006, SRVB Assy) | Disc/servo mechanism control — irrelevant to this project |
| `PANL` | Renesas-family MCU | DYW1817 (IC8003, PNLB Assy) | Buttons, LEDs, jog light — irrelevant to this project |

**The GUI (Blackfin) chip is the actual target** for any RGB-waveform patch, since it's
the one driving the screen. MAIN (SH4) matters only insofar as it's what reads USB
files and would need to forward color data to GUI over their internal link.

A key finding from the GUI firmware's own debug strings: it's linked against a
graphics middleware ("DS_G3 / GLib") that exposes a full RGB **palette API**
(`DS_GR_SetPaletteColor`, `DS_GR_CreatePalette`, `DS_GR_SetWindowPalette`, etc. — see
§5). This means the hardware/library stack is not fundamentally blue-only; the
restriction is very likely an application-level gate, not a capability gap. That's
the working hypothesis this project is chasing.

**CDJ-2000NXS2** was pulled in for comparison. Its GUI board is a genuine hardware
revision (touch panel added, doubled SDRAM, new IC numbering) — not just a firmware
difference. The **CDJ-3000/3000X are a different, later hardware generation** and are
not expected to be directly useful reference material for this chip pair.

---

## 2. `.UPD` container format

```
<GUI byte length>\r\n<DRIV byte length>\r\n<MAIN byte length>\r\n<PANL byte length>\r\n
<GUI segment bytes><DRIV segment bytes><MAIN segment bytes><PANL segment bytes>
```

- `MAIN`, `DRIV`, `PANL` segments are Motorola **S-record** (SREC) text, each preceded
  by a short ASCII header (`"CDJ-2000NXS <NAME>Ver<version>"`).
- `GUI` segment is a raw/packed **Blackfin LDR boot stream** (Analog Devices' native
  boot-loader container format — not SREC), also preceded by a short ASCII header.
- Each segment ends in what looks like a proprietary Pioneer trailer/checksum
  (unconfirmed algorithm — not yet reverse engineered). No cryptographic signature
  was found anywhere; the only "authentication" chip on the board (337S3959) is an
  Apple MFi accessory-auth chip for USB iDevice support, unrelated to firmware
  integrity.

NXS: `C2KNXS.UPD`, 9,565,083 bytes. Header: `2015268 / 388690 / 7062204 / 98888`
(GUI/DRIV/MAIN/PANL).
NXS2: `C2KNXS2.UPD`, 16,768,854 bytes. Header: `6931940 / 388690 / 9347916 / 100274`.

---

## 3. MAIN CPU (SH-4A) — status

- Rebuilt as a flat memory image, base `0xA0000000` (SH-4 P2/uncached area), confirmed
  reset vector `0xA0000000` matches the SREC's S7 start-address record.
- **Important correction to an earlier (pre-this-session) assumption:** the firmware is
  actually **little-endian**, not big-endian. Disassembling with a big-endian
  assumption produces garbage; little-endian produces clean, recognizable SH-4 startup
  code (register-save prologue, SR setup, etc.) immediately. If a prior Ghidra session
  was configured for big-endian SH-4, that alone would explain a total analysis
  breakdown.
- Found `ANLZ` (at `0xA00B21F6`) and `PWAV` (at `0xA00B70EA`) ASCII strings, matching
  rekordbox's `.DAT`/`.EXT` analysis-file tag names. However: **no code anywhere in
  the image references either address**, by any addressing pattern tried (PC-relative
  load, raw pointer table). The surrounding bytes have the profile of a
  compressed/packed resource blob (localized UI strings), not a literal C string used
  by file-parsing logic. This was a dead end for finding the ANLZ tag-dispatch code
  directly; the actual tag-comparison code (if it does FourCC comparisons at all) has
  not been located.
- Not pursued further this session in favor of focusing on GUI, since GUI is the
  higher-value target.

---

## 4. GUI CPU (Blackfin ADSP-BF531) — container format cracked

### 4.1 LDR block format (confirmed against real source, not guessed)

Verified against actual U-Boot kernel source
(`common/cmd_bootldr.c`, BF53x LDR loader) and GDB/binutils
(`include/opcode/bfin.h`, `opcodes/bfin-dis.c`):

- Each block: 10-byte little-endian header — `addr` (u32), `count` (u32), `flags`
  (u16) — followed by `count` bytes of body data (**except** when the `ZEROFILL` flag
  is set, in which case there is no body in the file at all; `count` bytes of zero
  should be written to `addr` instead).
- Flag bits: `ZEROFILL=0x0001`, `RESVECT=0x0002`, `INIT=0x0008`, `IGNORE=0x0010`,
  `FINAL=0x8000` (marks the last block of a DXE; multiple DXEs can be concatenated in
  one LDR, each new one starting with an `IGNORE`-flagged block).
- Instruction words and immediates are little-endian (Blackfin is little-endian by
  spec, unlike SH-4 which is configurable).

### 4.2 NXS's GUI firmware: uncompressed, fully readable

Applying the above, NXS's ~1.9MB GUI segment parses cleanly start-to-finish as plain
LDR blocks — confirmed by walking ~1000 consecutive blocks with sane, monotonically
sensible destination addresses the whole way through. Real memory image successfully
reconstructed (~915KB of actual code/data across 382 non-zerofill blocks).

### 4.3 NXS2's GUI firmware: compressed, NOT yet crackable

NXS2's GUI segment (~6.9MB, vs NXS's ~1.9MB) has high byte-entropy (~7.0–7.6 bits/byte)
almost from the first byte, and none of the standard block-header heuristics find a
valid chain more than 1–2 blocks deep. This matches Analog Devices' **documented
"Compressed Streams"** LDR feature (see `CrossCore Embedded Studio Loader and
Utilities Manual`, §"ADSP-BF531/532/533/534/536/537 Processor Compression Support") —
a real, standard toolchain feature, not bespoke Pioneer encryption. **Algorithm not
yet identified/implemented.** This is the blocker for any direct NXS-vs-NXS2 code diff.
It's also possible some of NXS2's size growth is just more embedded JPEG assets for
the touchscreen UI (188 JPEG magic-byte hits found), but the pre-JPEG regions are
*also* high-entropy, so compression of the executable itself looks real, not just an
artifact of embedded images.

### 4.4 Blackfin disassembler

Built from scratch (`bfindis.py`) using the **exact bit-field tables** from GDB/binutils'
`include/opcode/bfin.h` — not reconstructed from memory. Covers: `ProgCtrl` (NOP,
RTS/RTI/RTX/RTN/RTE, `JUMP (Pn)`, `CALL (Pn)`), `PushPopReg`/`PushPopMultiple`
(prologues), `BRCC`/`UJump` (branches), `RegMv`, `ALU2op`/`PTR2op`/`LOGI2op`/`COMP3op`,
`LDST`/`LDSTii`/`LDSTiiFP`/`LDSTpmod`/`DspLDST`/`LDSTidxI` (loads/stores),
`LDIMMhalf` (`reg.H = imm16` / `reg.L = imm16` — the idiom Blackfin code uses to build
32-bit constants, critical for finding what address a piece of code is touching),
`CALLa` (direct call/jump), `Linkage` (LINK/UNLINK), `LoopSetup`. `DSP32*` (MAC/ALU/
Shift, the 0xC-prefixed heavy DSP instructions) are recognized for length/boundary
purposes only, not semantically decoded — not needed for control-flow/address tracing,
but would need filling in for anything involving the actual pixel math.

Validated against the real, known-correct boot entry point (`0xFFA08000`, the
documented ADSP-BF531/532 default warm-boot address) — produces clean, idiomatic
output (register-save prologue, a delay loop, `CALL`s through computed pointers,
`RTI`).

---

## 5. What's been found in the GUI firmware's actual code

- **Palette/graphics API exists and is linked in:** debug strings for
  `DS_GR_SetWindowColor`, `DS_GR_SetColorSystem`, `DS_GR_SetLayerColor`,
  `DS_GR_GetPaletteColor`, `DS_GR_SetWindowPalette`, `DS_GR_SetLayerPalette`,
  `DS_GR_CreatePalette`, `DS_GR_DestroyPalette`, `DS_GR_SetPaletteColor` sit in GUI's
  rodata at file offsets `0x3640–0x3D44` (runtime `~0x00C6A7F8–0x00C6AEFC`). **However,
  exhaustive scanning of the ~915KB decoded code found zero references to any of these
  addresses** — neither as a computed 32-bit constant (register-pair load) nor as a
  raw pointer in data. These are almost certainly compiler/debug-info leftovers, not
  something callable by name; the actual call sites (if any) must go through some
  other mechanism (numeric dispatch table, indirect call via a structure Claude hasn't
  traced yet, etc.).
- **Master hardware-init function** (around `0x00D129B2`) calls, in order: SIC wakeup
  setup (`0x00D0C3E2`), SDRAM controller init (`0x00D0C420` — standard
  `EBIU_SDRRC`/`SDBCTL`/`SDGCTL` boilerplate), async memory bank timing
  (`0x00D0C45E`), two not-yet-explored calls (`0x00D0C49E`, `0x00D0C224`), then a
  **SPORT1 (Synchronous Serial Port 1) full setup** (`0x00D0C548`):
  `SPORT1_TFSDIV=0x0010`, `SPORT1_TCR2=SPORT1_RCR2=0x020F` (~16-bit word length),
  `SPORT1_TCR1=0x2602`, `SPORT1_RCR1=0x6400`.
- **Paired SPORT1-receive-interrupt enable/disable functions** at `0x00D0C5F2` /
  `0x00D0C61E` (toggle a bit in `SIC_IMASK` plus a bit in `SPORT1_RCR1`).
- **A GPIO interrupt priority-encoder** (`~0x00D0C1D0–0x00D0C3BE`): reads
  `FIO_FLAG_D` (0xFFC00700), tests bits 15 downward, and for the first pin found set,
  clears just that pin via `FIO_FLAG_C` (0xFFC00704) and returns. Generic "which of
  several GPIO sources fired" dispatcher, not SPORT-specific by itself.
- **DMA channel 5 gets cleared very early in the boot bootstrap stub**
  (`0xFFA08018`), suggesting it may later be set up for automatic SPORT1-receive
  transfers — not yet confirmed with real transfer parameters or a destination buffer
  address.
- **Not yet found:** any direct read of `SPORT1_RX` (0xFFC00918) or
  `SPORT1_STAT` (0xFFC00930), the actual interrupt service routine body, the DMA5
  descriptor/buffer setup, or any call site for the `DS_GR_*` palette functions. This
  is the current working edge — SPORT1 is confirmed configured and its interrupt
  armed, but the code that actually consumes incoming words hasn't been located.

**Working theory, unconfirmed:** MAIN CPU streams data to GUI CPU over SPORT1
(a real synchronous serial link, not a bit-banged GPIO signal), GUI CPU receives it
(possibly via DMA5), and somewhere downstream that data reaches drawing code that may
or may not call into the confirmed-present `DS_GR_*` palette API. Whether the
blue-only limitation lives in "MAIN never sends color data" or "GUI receives it but
never calls the palette functions" is still open.

---

## 6. Tooling produced this session (Python, self-contained, no external deps)

- `srec_parse.py` — Motorola S-record parser (for MAIN/DRIV/PANL segments).
- `sh4dis.py` — SH-4 disassembler (little-endian, ~140 instruction forms covered).
- `bfindis.py` — Blackfin disassembler built from GDB/binutils' `opcode/bfin.h` tables.
- `track_p.py` — scans decoded Blackfin code for pointer-register values (both fresh
  32-bit loads and small `+=`/`=` offset adjustments) that resolve to known
  memory-mapped peripheral register addresses, to find what hardware a given function
  actually touches without needing symbol names.

All were built and validated in-session against real, known-correct reference points
(verified reset vectors, official register maps) rather than assumed from memory.

## 7. Key external references used

- CDJ-2000NXS / CDJ-2000NXS2 official service manuals (chip identification, block
  diagrams).
- U-Boot kernel source, `common/cmd_bootldr.c` (BF53x LDR block flag definitions).
- GDB/binutils source, `include/opcode/bfin.h` and `opcodes/bfin-dis.c` (authoritative
  Blackfin instruction encoding).
- Linux kernel `arch/blackfin/mach-bf533/include/mach/defBF532.h` (authoritative
  ADSP-BF531/532/533 memory-mapped register addresses).
- Analog Devices *Blackfin Processor Programming Reference*, Rev 2.2 (instruction
  semantics, register conventions).
- Analog Devices *CrossCore Embedded Studio Loader and Utilities Manual* (LDR
  compressed-stream feature, confirming NXS2's compression is a standard toolchain
  option, not custom encryption).

## 8. Suggested next steps for a fresh pair of eyes

1. Track down the SPORT1-receive consumer: either widen pointer-tracking to catch
   more addressing idioms, or manually walk forward from the enable-interrupt call
   site to find where the interrupt vector actually points (Blackfin `EVTn` core MMRs,
   `0xFFE02000`+).
2. Find the DMA5 descriptor setup (`DMA5_START_ADDR`, `DMA5_X_COUNT` etc.) if SPORT1
   is DMA-fed rather than CPU-polled.
3. Once a receive buffer is found, trace forward to see what interprets it — that's
   the most direct route to the actual color/blue-only decision point.
4. In parallel: identify the ADI LDR "Compressed Streams" algorithm to unlock a real
   NXS-vs-NXS2 code diff, which would likely shortcut a lot of the above.


---

# ADDENDUM — Session 2

## A. CORRECTION to Session 1 findings (important)

Session 1's "literal address scan" (`track_p.py`) assumed Blackfin builds 32-bit
constants as `.H` first then `.L`. **The compiler in this firmware emits `.L` first,
then `.H`.** The old scanner therefore paired the *high* half of one constant with the
*low* half of the **next** one. Because consecutive constants usually share a high
half (e.g. everything in `0xFFC0xxxx`), the resulting values often still looked
plausible — which is why the error went unnoticed.

**What survives:** the broad conclusions. SPORT1 *is* configured and its RX interrupt
*is* armed; DMA0 *is* the PPI/LCD feed; the framebuffer address is solid (it was read
directly out of a DMA descriptor in data, not via half-pairing).

**What does NOT survive:** the exact instruction addresses attributed to each register
reference in §5 of the original notes. Re-derive any of those before relying on them.

## B. MAIN (SH-4) data section is LZSS-compressed — confirmed

This resolves Session 1's biggest dead end (`ANLZ`/`PWAV` strings present but
referenced by nothing).

Format, verified empirically — 8 consecutive group-boundary predictions landed exactly:
- stream = sequence of groups; each group = 1 flag byte then 8 items, **LSB-first**
- flag bit 1 -> literal (1 byte); flag bit 0 -> match (2 bytes: 12-bit ring position +
  4-bit length)
- classic Okumura LZSS (N=4096, F=18, THRESHOLD=2)

Anchor: a valid group boundary exists at file offset `0xB21D5` in the reconstructed
`MAIN.bin` (base `0xA0000000`). Decompressing from nearby yields genuine strings
(`Music Analyse File is broken`, `/ANLZ%04X.`, plus Shift-JIS Japanese UI text).

**Unsolved:** the true start of the compressed stream. Flag-walking is
self-synchronising, so thousands of offsets "walk" validly but give a wrong ring-buffer
history, leaving back-references corrupted. Output is ~70% clean, not 100%. Fixing this
needs either (a) locating the decompressor routine in SH-4 code and reading its source
pointer argument, or (b) finding the blob header/size fields. **This is the single
highest-leverage unblock available** — it would make the string tables of both NXS and
NXS2 readable and enable a real feature comparison.

## C. Control experiment: absence of PWV4/PWV5 is NOT evidence

Searched both firmwares for rekordbox analysis tags (`PWAV`, `PWV2`-`PWV5`, `PCOB`,
`PCO2`, `PSSI`, `PQTZ`...) in **both** byte orders (forward, and reversed as a
little-endian 32-bit compare constant).

Result: essentially nothing in either image — **including in the NXS2, which
demonstrably does render RGB waveforms.** Since the NXS2 must contain this logic, the
zero-hit result is explained by compression, not by absent functionality. Any claim of
the form "the NXS firmware doesn't know about colour waveforms" is therefore
**unsupported** by the evidence gathered so far.

## D. New tooling

- `dataflow.py` — intra-function abstract interpretation for Blackfin: propagates
  constants through register moves, `+=`/`=` immediates, and FP-relative stack
  spill/reload; resolves load/store effective addresses. Handles `.L`/`.H` in either
  order via a known-half mask, plus the full-register `(Z)`/`(X)` form. On the known
  window-struct it finds **16** accesses where the old literal scan found 2.
- `lzss.py` — LZSS decompressor + group-boundary walker for MAIN.
- `harness.py` — loads the GUI LDR image, decodes all ranges, runs dataflow queries.

## E. Current hard blocker

Scanning the entire graphics SDRAM window found 81 resolved accesses — **all of them
to global variables** (`0x00653C84`–`0x00658C84`), **none to the framebuffer itself**
(`0x00659B88`+). This is expected and diagnostic: real drawing code computes pixel
addresses (`base + y*stride + x`) from a pointer held in a variable or passed as an
argument. Constant tracking within a single function fundamentally cannot resolve those.

Reaching the waveform renderer therefore needs **inter-procedural** analysis (propagate
values across call boundaries, track pointers through the struct at `0x00658C74`),
which is a substantially larger build than anything here so far.

## F. Honest scope assessment

No patch target has been identified, and none is close. Two possibilities remain open
and they differ enormously in effort:

1. *Best case* — MAIN already parses colour waveform data and GUI already knows how to
   render it, and something gates it (a model ID check, a config byte). Then a small
   patch could work.
2. *Likely case* — the NXS simply never implements the colour path. Enabling it would
   mean writing new `.EXT`/`PWV5` parsing on the SH-4, new messages in the MAIN->GUI
   protocol, and new rendering on the Blackfin — hand-written assembly across two
   different CPUs, with no ability to test before flashing.

**Nothing found so far distinguishes between these two cases.** Section C is
specifically a warning against concluding case 2 prematurely. Resolving B (proper
decompression, then a real NXS/NXS2 string-table diff) is the cheapest way to find out
which world we are in, and should come before any further disassembly grinding.


---

# ADDENDUM — Session 3

## G. MAIN (SH-4) is ~90% compressed — this reframes all MAIN analysis

Byte-statistics sweep across the reconstructed `MAIN.bin` (16 equal regions):

- `0x000000`–`0x05C298`: entropy ~5.85–5.98, high 0xFF (our gap padding) — **plain code**
- `0x05C298`–`0x2E14C0` (the remaining ~87%): entropy **7.55–7.71**, uniformly — **compressed**

Corroborating: the 32-bit value `0x00001000` appears **zero** times in the whole 3MB
image, as do `0x00000FFF` and `0x00000FEE`. Only 1.7% of bytes are zero. Those figures
are impossible for ordinary firmware (which is full of zero padding, null terminators
and small constants) and are diagnostic of packed data.

**Consequences:**
1. Session 1's "no code references the `ANLZ`/`PWAV` strings" is now *fully* explained
   and should not be treated as a finding about functionality. Those strings sit inside
   the compressed blob (entropy 7.70 in that region).
2. Any search of `MAIN.bin` for strings, tags or constants is near-worthless until the
   blob is decompressed. This retroactively weakens **every** negative result obtained
   by searching MAIN, not just the tag search in §C.
3. The plain-code window (roughly `0xA0010000`–`0xA005C298`) is where the boot stub and
   the decompressor must live. That is now the only part of MAIN worth disassembling
   directly.

## H. LZSS parameter search — partial, not solved

Confirmed structure (flag byte + 8 LSB-first items; bit=1 literal, bit=0 two-byte match)
is solid — verified against a known group boundary at file offset `0xB21D5`.

Match *semantics* are not solved. Tested exhaustively:
- ring-buffer (absolute 12-bit index) vs LZ77 (backward distance), all four nibble
  layouts, min-length 2 and 3, MSB/LSB-first flags, fill `0x20`/`0x00`
- brute-forced all 4096 ring start positions (this matters permanently, not just for the
  first window: a wrong ring phase corrupts every back-reference forever)

Best result: ring-buffer, `dist = lo | ((hi & 0x0F) << 8)`, `len = (hi >> 4) + 3`,
ring start 3792 — **88.9%** plausible-byte score vs a 77% baseline. Real strings emerge
(`PlayerTASK`, `EjectLock`, `JogTouch`, `TempoRange`, `Rekordbox`, `<ver>1.00</`,
`SDdoorOpen`, `Music Analyse File is broken`, `/ANLZ%04X.`) but matches still resolve
wrongly in places. **No sharp peak** was found, which normally means a format detail is
still wrong rather than merely mis-parameterised.

Attempt to find the decompressor routine by searching for ring-mask constants
(`0xFFF`/`0x1000`) in SH-4 literal pools returned **nothing** — consistent with §G
(those constants would be inside the compressed region if the decompressor is itself
loaded late, or the mask is computed rather than loaded).

**Recommended next step:** disassemble the plain-code window `0xA0010000`–`0xA005C298`
directly and locate the decompression routine by shape (flag-byte shift/test loop,
two-byte match fetch, ring pointer advance). Reading the algorithm out of the code is
now clearly cheaper and more reliable than continuing to infer it statistically.


---

# ADDENDUM — Session 4: MAIN decompressor located and read

## I. The decompressor is at `0xA0000700` — algorithm read from code, not inferred

Boot flow reconstructed from the ~2.3KB of genuine SH-4 code (`0x100`-`0x620`,
`0x700`-`0xA20`; everything else in MAIN is compressed payload):

1. `0xA0000100` — peripheral + SDRAM init, then a `0x55555555`/`0xAAAAAAAA` memory test
   (`0xA0000298`).
2. `0xA00004FC` — **DMA-accelerated memcpy** (programs SH7764 DMAC at `0xFF608060`:
   SAR +0x20, DAR +0x24, TCR +0x28, CHCR +0x2C, polls TE). Signature `(src, dst, len)`.
3. Called twice: `(0xA0040000, 0xA7A00000, 0x3A0000)` — copies the compressed payload to
   RAM; and `(0xA0000700, 0xABFFD000, 0x1000)` — relocates the decompressor block.
4. Jumps via pointer at `0xA0000618` = `0x0BFFD1A6`, i.e. offset `0x1A6` into the
   relocated block == `0xA00008A6` in-file. **This is the orchestration code and has not
   yet been read — see §K.**

**`0xA0000700` is textbook Okumura LZSS**, confirmed instruction by instruction:
- ring buffer at `0x0BFFD310`, pre-filled with `0x20` (space) for **4078** bytes
  (2039 iterations x 2 bytes/iter)
- `r` initialised to `0x1000 - 18 = 0xFEE = 4078` (N-F); mask `R1 = 0xFFF`
- flag handling is the classic counter trick: `flags >>= 1; if !(flags & 0x100) {
  flags = *src++ | 0xFF00 }` -> **LSB-first, bit=1 means literal**
- match: `pos = lo | ((hi & 0xF0) << 4)`; copy loop runs `(hi & 0x0F) + 3` times
  (verified by tracing the `CMP/GT`/`BF/S` loop bounds)
- both paths write into the ring at the pre-increment `r`, then `r = (r+1) & 0xFFF`

This is **variant A** with `r_init = 4078`, fill `0x20` — settling the parameter search
in §H by reading the machine rather than scoring guesses.

## J. Result: decompression largely works, degrades after 4096 bytes

Decompressing from file offset `0x40000` yields ~4.06 MB. Verified-correct content:
- `CDJ-2000NXS` and `1.44` (model + firmware version) — exact
- `PIONEER/rekordbox/exp...` (USB export path), 52 `rekordbox` hits
- Pioneer internal build paths: `:\CDJ\Build_...`, `2KNXS\DB\`, `\cue\src\`
- `/ANLZ%04X.`, `Music Analyse File is broken`

SH-4 decode validity by output offset: **95.4% and 95.3%** for the first two 2KB
windows, then a sharp drop to ~75% and staying there. The transition is at **exactly
`0x1000` = 4096 = the ring-buffer size**, which is diagnostic rather than random.

## K. Remaining issue and next step

Two candidate explanations for the post-4096 degradation:
1. **Multiple concatenated streams.** The payload is probably decompressed as several
   separate blocks (each re-initialising ring and `r`), so running one continuous
   decode desyncs after the first block ends. The orchestration code at `0xA00008A6`
   would contain the block table (source offsets, destinations, sizes).
2. Ring bytes `0xFEE`-`0xFFF` are left uninitialised by the firmware (only 4078 of 4096
   are space-filled); this decode fills all 4096. Small, but affects early matches.

**Next step: disassemble `0xA00008A6`** (the relocated orchestrator) to recover the
block table. That is a small, bounded piece of real code and would very likely take
decompression from ~partial to exact.

Once MAIN decompresses cleanly, the original blocking questions become answerable for
the first time: whether the NXS parses `.EXT`/`PWV4`/`PWV5` at all, and a genuine
NXS-vs-NXS2 comparison (NXS2's MAIN is SREC and very likely uses the same scheme).


---

# ADDENDUM — Session 5: MAIN fully decompressed. Central question ANSWERED.

## L. Container format solved end-to-end (checksum verified)

Payload layout at file offset `0x40000` in the reconstructed `MAIN.bin`:

```
0x40000  u32  compressed length (LE)          = 0x2A14B1
0x40004  ...  LZSS stream (length bytes)
end      u16  checksum (LE)                   = 0xF05D
```

The boot code's own checksum routine is a plain **16-bit sum of all bytes over
(length + 4)**, i.e. the header plus the stream. **Computed 0xF05D == stored 0xF05D.**
That match is independent proof the format, boundaries and algorithm are all exactly
right. Decompressed output is exactly **0x3E0000 (4,063,232) bytes**, loaded to
**`0xA4000000`**.

Boot sequence: raw payload DMA-copied flash->RAM, decompressor block relocated to
`0xABFFD000`, entered at `0x0BFFD1A6`; orchestrator at `0xA00008A6` reads the length
header, verifies the checksum, then calls the LZSS routine
`(src = payload+4, dst = 0xA4000000, len)`. On checksum failure it takes a fallback
raw-copy path.

Decompression quality is now unambiguous - clean, complete strings throughout, e.g.
`D:\CDJ\Build_CDJ2KNXS\DB\cache\cue\src\msc_anlz_local_usb.c`,
`Music Analyse File is broken!!!\r\n`, an entire TCP/IP stack's diagnostics, and
UTF-16 tables (`PIONEER`, `USBANLZ`, `CHKANLZ`, `DISCANLZ`, `USBMNG.DAT`, `ANLZ`,
`DAT`, `EXT`).

## M. THE ANSWER: the colour waveform tags are absent, not gated

The ANLZ parser dispatch table (8-byte entries) recovered at `0x00ACE28` / `0x00ACEBC`
in the decompressed image reads, in order:

```
PMAI  PPTH  PVBR  PQTZ  PWAV  PWV2  PCOB  PWV3  PKEY  PCO2  PCPT  PCP2
```

Tag census across the whole clean 4MB image:

| tag | meaning | present |
|---|---|---|
| PWAV | waveform preview (blue, .DAT) | yes (6) |
| PWV2 | waveform preview tiny (.DAT) | yes (5) |
| PWV3 | scrolling waveform detail (blue, **.EXT**) | yes (3) |
| PCO2 | extended cues (**.EXT**) | yes (4) |
| PCOB, PMAI, PPTH, PVBR, PQTZ, PKEY | misc | yes |
| **PWV4** | **colour waveform preview (.EXT)** | **NO - 0 occurrences** |
| **PWV5** | **colour waveform detail (.EXT)** | **NO - 0 occurrences** |
| PSSI | phrase/song structure | no |

This **settles the case-1-vs-case-2 question from Section F**. It is **case 2**: the
CDJ-2000NXS firmware contains no parser entry and no handler for the colour waveform
tags. This is not a disabled feature behind a model gate - the code to consume that
data does not exist in this firmware.

The §C warning still stands as a matter of method: this conclusion is only valid
*because* the image is now verifiably, completely decompressed (checksum-proven). The
identical search on the compressed image was worthless.

**Important mitigating finding:** the NXS *does* already open and parse the `.EXT`
analysis file - `PWV3`, `PCO2` and `PKEY` are all `.EXT`-resident tags, and `EXT`
appears in the UTF-16 extension table. So the file discovery, opening, and
tag-walking infrastructure for the file that *contains* the colour data is present and
working. What is missing is specifically: the two tag entries, their handlers, storage
for the colour data, transport of it to the GUI CPU, and colour rendering on the
Blackfin.

## N. Realistic assessment of the remaining work

To add RGB waveforms would now require, in order:
1. New `PWV4`/`PWV5` entries + handler code in the SH-4 ANLZ parser (hand-written
   assembly, or injected compiled code, into a decompressed-then-recompressed image).
2. Storage and a new message type in the MAIN -> GUI protocol (SPORT1) to carry
   per-column colour rather than the current height/whiteness pair.
3. Colour rendering on the Blackfin GUI CPU (the `DS_G3` palette API exists but, per
   §5/§E, nothing currently calls it and the renderer has not been located).
4. Re-compress the MAIN payload (or pad/relocate), fix the 16-bit payload checksum
   (**algorithm now known**), and additionally solve the outer `.UPD` per-segment
   trailer (**still unknown**).
5. Flash with no ability to test first - unlike the CDJ-3000 work, this platform is
   bare metal, so there is no root, no runtime hooking, no staged/one-shot install and
   no automatic revert. Recovery is reflashing stock.

This is implementing a cross-processor feature in assembly, blind. It should be
regarded as very unlikely to be completed this way, and that judgement is now based on
a known firmware structure rather than on speculation.


---

# ADDENDUM — Session 6: NXS vs NXS2 comparison (closes the question)

## O. Same container, same compression — NXS2 decompressed too

The NXS2's MAIN segment uses the **identical** container: `u32` compressed length,
LZSS stream, `u16` 16-bit byte-sum checksum. Payload located at offset `0x50000`
(vs `0x40000` on NXS) purely by brute-force checksum verification:
`len = 0x369CEB`, checksum `0x9499`, **verified**. Decompresses to
`0x573DD4` (5,717,460 bytes) vs the NXS's `0x3E0000`.

Quality confirmed by content: same TCP/IP stack diagnostics, model string
`CDJ-2000NXS2MAIN`, `/%s/CDJ/CDJINDX%d.PDJ`, etc.

## P. Tag-by-tag diff — one difference, and it is exactly the colour waveform

| tag | NXS | NXS2 |
|---|---|---|
| PMAI | 7 | 7 |
| PPTH | 6 | 6 |
| PVBR | 5 | 5 |
| PQTZ | 5 | 5 |
| PWAV | 6 | 6 |
| PWV2 | 5 | 5 |
| PWV3 | 3 | 3 |
| PCOB | 7 | 7 |
| PCO2 | 4 | 4 |
| PKEY | 4 | 4 |
| PCPT | 5 | 5 |
| PCP2 | 4 | 4 |
| PSSI | 0 | 0 |
| **PWV4** | **0** | **1** |
| **PWV5** | **0** | **1** |

**Every single other tag matches exactly.** Thirteen tags, identical counts — the same
codebase, the same parser, the same analysis-file handling. The only difference in the
entire ANLZ tag surface is the presence of `PWV4` and `PWV5`.

In the NXS2 image those two sit in a small dedicated table alongside the file
extension:

```
PWV5 \0\0\0\0 EXT \0 PWV4
```

i.e. an explicit "colour waveform tags live in the .EXT file" association that has no
counterpart anywhere in the NXS image.

## Q. Conclusion

This is a clean, controlled result: two firmwares from the same codebase, decompressed
by the same verified method, differing in exactly the feature under investigation.

The CDJ-2000NXS does not contain a disabled or gated colour-waveform capability. The
supporting code was added for the NXS2. There is nothing in the NXS firmware to
switch on, and consequently no small patch that could enable RGB waveforms.

The earlier caution in §C was correct and worth having: on the *compressed* images
this same comparison returned zero hits for both units and would have produced the
right answer for entirely the wrong reason. The result above is only meaningful
because both images are checksum-verified decompressions.


---

# ADDENDUM — Session 7: outer .UPD checksum solved

## R. Per-segment trailer = CRC16-XMODEM (big-endian)

Tested standard algorithms against every segment trailer in both firmwares:

| segment | NXS trailer | NXS2 trailer | algorithm |
|---|---|---|---|
| GUI  | `41ED` | `825C` | CRC16-XMODEM |
| DRIV | `CEE9` | `7373` | CRC16-XMODEM |
| MAIN | `A9D7` | `A31A` | CRC16-XMODEM |
| PANL | `8A13` | `F110` | CRC16-XMODEM |

**CRC16-XMODEM** = poly `0x1021`, init `0x0000`, no reflection, no final XOR; stored
**big-endian** as the last two bytes of the segment.

Coverage: the CRC is computed over the whole segment up to the CRC field. Seven of the
eight segments use a plain 2-byte trailer. The exception is **NXS GUI**, where the CRC
covers `segment[:-4]` — i.e. there is an additional 2-byte field (`0x0000`) between the
body and the CRC. NXS2 GUI uses the plain 2-byte form, so this appears to be a
per-build quirk rather than a GUI-segment rule; check the last 4 bytes of any segment
before assuming.

## S. Container format now fully documented

```
.UPD file
  ASCII header:  "<GUIlen>\r\n<DRIVlen>\r\n<MAINlen>\r\n<PANLlen>\r\n"
  GUI  segment:  "CDJ-<model>GUI Ver<x>"  + Blackfin LDR blocks + [pad] + CRC16-XMODEM(BE)
  DRIV segment:  "CDJ-<model>DRIVVer<x>"  + S-records              + CRC16-XMODEM(BE)
  MAIN segment:  "CDJ-<model>MAINVer<x>"  + S-records              + CRC16-XMODEM(BE)
  PANL segment:  "CDJ-<model>PANLVer<x>"  + S-records              + CRC16-XMODEM(BE)

MAIN payload (inside the S-record image, at 0x40000 NXS / 0x50000 NXS2)
  u32  compressed length (LE)
  ...  LZSS stream (Okumura: N=4096, F=18, THRESHOLD=2, ring fill 0x20,
       r init 0xFEE, flags LSB-first with |0xFF00 counter, bit=1 literal,
       match pos = lo | ((hi & 0xF0) << 4), len = (hi & 0x0F) + 3)
  u16  16-bit byte sum over (length field + stream), LE
```

Every field above has been verified by recomputation against both firmwares.

## T. What this enables — and what it does not

A structurally valid, fully checksum-correct `.UPD` can now be built entirely offline.
That removes the last *known* barrier to producing a flashable image.

It does **not** establish that the deck will accept such an image. Unknowns that
remain, all of which can only be settled on hardware:
- whether the updater performs additional validation beyond these checksums
  (version/model gating, per-segment magic, size expectations)
- whether a re-compressed MAIN payload of a *different length* to stock is acceptable
  (our LZSS encoder will not reproduce Pioneer's exact output; the length header and
  both checksums adapt, but any hard-coded size or offset assumption elsewhere would not)
- what the boot stub's checksum-failure fallback path actually does, and therefore
  whether a bad flash is recoverable in-place

**Recommended validation order, all offline first:**
1. Reassemble the *unmodified* `.UPD` from parsed components and confirm it is
   **byte-identical** to the original. Proves the container pipeline with zero risk.
2. Write an LZSS *compressor*, round-trip it (compress -> decompress -> compare to the
   known-good decompressed image) until byte-identical. Proves the codec.
3. Rebuild a functionally-identical-but-not-byte-identical image (re-compressed MAIN),
   verify all checksums recompute correctly.
4. Only then consider hardware, and only on a deck whose loss is acceptable.
