# Task list

Convert these to GitHub Issues once the repo exists — they're written to be pasted
one-per-issue. Suggested labels in brackets.

---

## Phase 0 — offline lab

- [x] **Make analysis tools import-safe and location-independent.** Remove the
      original `/home/claude/work` assumptions and firmware I/O during module import.
      `[tooling]`
- [x] **Add strict offline inspection.** Validate `.UPD` lengths, segment CRCs,
      S-record checksums, MAIN byte-sum and LZSS decompression. `[tooling]`
- [x] **Add `PWV4`/`PWV5` parsing and PNG rendering.** Synthetic tests pass; real
      `.EXT` comparison is still required. `[tooling] [inferred]`
- [ ] **Validate the lab with real inputs.** Run against user-supplied stock firmware
      and an RGB-enabled rekordbox `.EXT`, then compare the PNG with rekordbox/NXS2.
      Firmware and `.EXT` structure now pass; the same-track screenshot comparison is
      still outstanding. `[analysis] [blocker]`

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

## Phase 2 — targeted PWV3 trace (no firmware changes)

- [x] **Build project-local GNU SH-4 binutils.** KallistiOS stable Dreamcast profile,
      binutils 2.45.1; validate `0xA4388E5C` and all four lookup sites. `[toolchain]`
- [x] **Map validators, callers, and generic dispatch.** Three validator functions,
      their wrappers/request IDs, the 12-entry tag table, classifier, and dedicated
      PWV3 branch are recorded in FINDINGS §6b. `[analysis]`
- [x] **Recover PWV3 metadata storage.** The 24-byte owner descriptor and real EXT
      sizes are proven; indexing advances over the payload rather than allocating or
      copying it. `[analysis]`
- [x] **Separate WAVE and CUE GUI paths.** The 900-byte CWCASH path feeds WAVE message
      ID 4 through `0xA4260C82`; the fully traced 103×36-byte table feeds CUE message
      ID 5 through `0xA4260D94`. Neither is direct PWV3 payload flow. `[analysis]`
- [x] **Find the real PWV3 post-index accessor and GUI constructor.** `0xA42AC380`
      seeks to the retained locator plus header length, allocates and reads the full
      PWV3 payload. `dbcl_GetParWaveData` carries it to track object `+0x5A4`, and
      `0xA425BD60`/`0xA425C0CC` copy raw bytes into 896-byte detailed-waveform frames.
      `[analysis] [milestone]`
- [x] **Build an offline NXS detailed-waveform emulator.** Generate, CRC-check and
      reassemble the exact 896-byte stock frame envelope, including reusable-buffer
      tail behavior. The canonical 29,804-byte PWV3 sample round-trips through 34
      frames byte-identically. `[tooling] [milestone]`
- [x] **Confirm the GUI physical ingress and command-32 receiver.** SPORT1/DMA3 takes
      a 64-byte transport header followed by the 896-byte frame, CRC-checks it, and
      dispatches command 32 to `0x00D0FA64`. It reassembles raw PWV3 at `0x01A65168`;
      event 32 reaches first consumer `0x00D2F51C`. `[analysis] [milestone]`
- [ ] **Name the final MAIN generic-send routine.** Receiver-side proof closes the
      data-format boundary, so this is useful call-graph cleanup rather than a blocker.
      `[analysis] [low-priority]`
- [ ] **Capture Ethernet twice.** Same track and phase timeline; scan both PCAPs with
      `tools/ethernet_trace.py`. A repeated absence is still evidence. `[hardware]`

## Phase 3 — code injection

- [x] **Write a hash-gated offline patch builder.** It assembles the Blackfin blobs,
      patches MAIN and GUI, recompresses MAIN, rebuilds the four-segment container,
      and verifies every checksum. Its output is explicitly not hardware-approved.
      `[tooling] [milestone]`
- [ ] **Inject a no-op routine.** Place in free space (`0xA40D57C4`, 174 KB of `0xFF`),
      redirect one harmless call, have it chain to the original. Pass = deck still
      boots. `[hardware] [milestone]`
- [ ] **Make it observable.** Something visibly different on screen, so success is
      distinguishable from "didn't crash". `[hardware]`

## Phase 4 — the remaining unknowns

- [ ] **Chase the serial debug console.** FINDINGS §8c: `232C Mode Change`,
      `phy debug command (usage: phy <r|w|s|l>)`, `diag_ether`. Usage strings imply a
      command interpreter. If reachable this could replace much of the hardware
      instrumentation below. **Do this before buying test gear.** `[analysis] [high-value]`
- [ ] **Locate the updater's validation code** in the decompressed image. Would explain
      any rejection, and confirm exactly what it checks. `[analysis]`
- [x] **Decode the detailed-waveform MAIN↔GUI protocol.** The raw PWV3 constructors,
      SPORT1/DMA3 ingress, CRC gate, command-32 receiver, reassembly, completion event,
      and first one-byte-to-12-byte column transform are all mapped. `[analysis]`
- [x] **Find the final GUI waveform renderer.** `0x00D2E230` reads the height and
      three-bit palette index from records at `0x01011940`, selects an RGB555 word at
      `0x00CD3928`, and writes it vertically into the 400×90 layer at `0x01000000`.
      The generic layer-to-DMA compositor remains separate cleanup. `[analysis]`
- [ ] **Crack the NXS2 GUI segment compression** (ADI "compressed streams"). The one
      remaining unknown in the container format. Not on the critical path.
      `[analysis] [low-priority]`

## Phase 5 — the actual feature

- [x] **Prototype PWV5 acceptance on SH-4.** Reuse the generic two-byte-entry parser by
      changing the three shared lookup literals. `[offline-only]`
- [x] **Carry the full PWV5 payload through MAIN→GUI.** Patch `0xA425B9EA` to use
      descriptor payload byte count rather than entry count; the real 59,608-byte EXT
      round-trips in 68 frames. `[offline-only]`
- [x] **Prototype an RGB555-per-column renderer source.** Receive PWV5 into the stock
      record arena, expand it backwards into 12-byte records with RGB555 at `+4`, and
      redirect `0x00D2E230`. `[offline-only]`
- [ ] **Pass the sacrificial-deck gates.** Prove recovery, then no-op injection, then
      68-frame load, zoom, seek, unload, and repeated-track stress. `[hardware] [blocker]`
- [ ] **Generalise beyond the 29,804-column ceiling.** The stock clear proves a
      10,800,600-byte arena; now prove all live users and add safe handling/fallback
      for different tag availability and lengths.
- [x] **Build the Blackfin toolchain and offline colour renderer hook.** The generated
      consumer is machine-code audited during every candidate build. `[offline-only]`

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
