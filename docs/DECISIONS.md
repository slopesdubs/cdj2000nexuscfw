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
