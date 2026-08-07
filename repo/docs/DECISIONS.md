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
