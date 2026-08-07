# Task list

Convert these to GitHub Issues once the repo exists — they're written to be pasted
one-per-issue. Suggested labels in brackets.

---

## Phase 1 — prove the flash pipeline (needs sacrificial deck)

- [ ] **Acquire a sacrificial CDJ-2000NXS.** Confirm it powers on and boots before
      doing anything to it. Record its current firmware version. `[hardware]`
- [ ] **Prepare recovery media.** Stock v1.44 from the official support site, on a
      FAT/FAT32 USB stick. Verify the download's hash against the copy the analysis was
      done on. `[hardware] [blocker]`
- [ ] **Baseline: official stock update.** Flash unmodified stock via
      MEDIA SELECT/USB + RELOOP. Proves the procedure, the stick and the deck before any
      custom image is involved. `[hardware]`
- [ ] **Flash the v1.45 rebuild.** Pass = deck displays 1.45.
      **This is the project's key milestone** — it proves decompress → edit →
      recompress → checksum → flash → observe end to end. `[hardware] [milestone]`
- [ ] **Prove recovery.** Deliberately return to stock and confirm it takes. Do this
      *before* anything riskier. `[hardware]`
- [ ] **Test the MAIN-only file.** `C2KNXSM_v145_MAINONLY.UPD` — its single-segment
      header layout is inferred, not verified. Confirms or refutes that reading.
      `[hardware] [unverified]`

## Phase 2 — code injection

- [ ] **Build the SH-4 toolchain.** See `docs/TOOLCHAIN.md`. Verify by disassembling
      stock firmware and matching FINDINGS §5. `[toolchain]`
- [ ] **Write a build script** that takes a decompressed image + a patch blob + a hook
      address and emits a flashable `.UPD`. Wraps `lzss_codec` and `upd_build`.
      `[tooling]`
- [ ] **Inject a no-op routine.** Place in free space (`0xA40D57C4`, 174 KB of `0xFF`),
      redirect one harmless call, have it chain to the original. Pass = deck still
      boots. `[hardware] [milestone]`
- [ ] **Make it observable.** Something visibly different on screen, so success is
      distinguishable from "didn't crash". `[hardware]`

## Phase 3 — the unknowns

- [ ] **Chase the serial debug console.** FINDINGS §8c: `232C Mode Change`,
      `phy debug command (usage: phy <r|w|s|l>)`, `diag_ether`. Usage strings imply a
      command interpreter. If reachable this could replace much of the hardware
      instrumentation below. **Do this before buying test gear.** `[analysis] [high-value]`
- [ ] **Locate the updater's validation code** in the decompressed image. Would explain
      any rejection, and confirm exactly what it checks. `[analysis]`
- [ ] **Decode the MAIN↔GUI protocol.** SPORT1 is configured and its RX interrupt armed
      (FINDINGS §6), but no consumer of received words was located. Logic analyser on
      the inter-board link. `[hardware] [instrumentation]`
- [ ] **Find the GUI waveform renderer.** Last unmapped subsystem. Needs
      inter-procedural analysis or a hardware watchpoint on framebuffer memory
      (`0x00659B88`). `[analysis] [instrumentation]`
- [ ] **Crack the NXS2 GUI segment compression** (ADI "compressed streams"). The one
      remaining unknown in the container format. Not on the critical path.
      `[analysis] [low-priority]`

## Phase 4 — the actual feature (blocked on Phase 3)

- [ ] Add `PWV4`/`PWV5` parser entries and handlers on SH-4.
- [ ] Extend the MAIN→GUI protocol to carry per-column colour.
- [ ] Blackfin toolchain + colour rendering on the GUI processor.

## Standing / anytime

- [ ] **Buy a logic analyser.** Cheap FX2-based 8-channel + Sigrok/PulseView, plus test
      hook clips. Verify current recommendations before ordering. `[hardware]`
- [ ] **Explore service mode** on the sacrificial deck (TEMPO + MEMORY at power-on).
      Zero risk, and shows what the deck exposes about itself. `[hardware]`
- [ ] **Improve `sh4dis.py` coverage.** It missed `sts.l pr,@-r15` among others; GNU
      binutils decodes more. Low priority now the real toolchain exists. `[tooling]`
- [ ] **Pick a licence** before the repo goes public. `[admin]`

---

## Notes on working style

Label every claim **verified** / **inferred** / **speculative**. Several early
conclusions in this project were confidently wrong — a big-endian assumption, a
mispaired half-word scan, and a tag search run against compressed data that returned
the right answer for entirely the wrong reason. All three looked convincing at the
time. Explicit confidence labels make them cheap to catch.
