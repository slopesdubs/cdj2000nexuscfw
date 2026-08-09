# Decisions log

Short entries. Date, what was decided, why. Append only — don't rewrite history,
add a superseding entry instead.

---

## 2026-08-07 — Firmware binaries stay out of the repo
Pioneer/AlphaTheta firmware is copyrighted. Each contributor supplies their own
stock `.UPD` from the official support site. Rebuilt and patched images are
derivative works and are also not committed. The repo holds tools and
documentation only; anyone can regenerate the firmware files by running the
tools against their own stock copy.

## 2026-08-07 — MAIN-only updates preferred for testing
`C2KNXSM.UPD` writes only the main CPU. DRIVE is the one processor with no
documented recovery path, so never include a DRIVE segment in a test image.

## 2026-08-07 — Target the version-string test before code injection
Editing a same-length string proves the decompress/recompress/checksum/flash
loop without requiring the toolchain or any assumptions about code placement.

## 2026-08-08 — Emulate the data path before attempting full-machine emulation
Current QEMU can execute SH-4 but does not model the CDJ's SH7764 board or its
Blackfin GUI system. The project will first emulate the observable pipeline — ANLZ
colour tags, proposed MAIN messages, and a 480-pixel framebuffer — while using strict
offline firmware validation. A full virtual deck is deferred unless this narrower lab
proves insufficient.

## 2026-08-08 — Finish the PWV3 trace before patch design
The original lookup sites are validators, while the real handler retains metadata and
advances over the payload. Patch design, signing, rebuilding, and flashing are deferred
until the remaining storage-to-GUI staging edge is proved or isolated. Ethernet is the
first hardware checkpoint, but a repeatable lack of waveform bytes there is accepted
as evidence because the internal MAIN-to-GUI stream need not traverse Pro DJ Link.

## 2026-08-09 — Reuse the waveform-record arena for the first colour prototype
The completed PWV3 trace exposed an exact low-impact seam, but the stock 36,824-byte
receive area is too small for canonical 59,608-byte PWV5. The first offline prototype
keeps command-32 framing, redirects reception to the 357,648-byte waveform-record
region needed by the canonical track inside the stock-cleared 10,800,600-byte arena,
hides its visible count on the first copy, and expands input backwards into
12-byte records after final-frame CRC validation. RGB555 lives at record `+4` and the
renderer reads it there. MAIN must use payload byte count rather than entry count, or
only half of PWV5 is transmitted. Stock initializer `0x00D2C0DE` proves the arena spans
`0x01011940`–`0x01A5E718` by passing `0x00A4CDD8` bytes to the byte-fill routine at
`0x00D4837C`. Record-arena lifecycle and doubled transfer timing remain explicit
hardware gates.

## 2026-08-09 — Generated PWV5 updates are inspection artifacts until hardware gates pass
The patch builder is intentionally hash-gated and marks its output not hardware-approved.
No candidate may be installed on a working deck. A sacrificial unit must first pass the
official-stock update, local rebuild, recovery, and chained no-op GUI injection tests.
The initial colour candidate is also limited to the canonical 29,804-column sample.
