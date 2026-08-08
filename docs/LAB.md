# Offline colour-waveform lab

This lab turns user-supplied firmware and rekordbox analysis files into inspectable,
testable artifacts without flashing a player. It uses only the Python standard library.

## Inputs

Create these ignored directories as needed:

```text
work/
  firmware/
    C2KNXS.UPD       # official stock NXS update supplied by the user
    C2KNXS2.UPD      # optional comparison control
  samples/
    ANLZ0000.DAT
    ANLZ0000.EXT     # export a track with RGB waveform enabled
```

The repository's `.gitignore` excludes `work/`, `.UPD`, `.DAT`-adjacent binary output,
and rebuilt images. Do not override those exclusions for copyrighted or device-derived
material.

## Verify the lab

From the repository root:

```bash
python3 -m unittest discover -s tests -v
```

The tests use synthetic inputs and do not require Pioneer/AlphaTheta firmware.

## Inspect and unpack firmware

Validate the container, all four segment CRCs, MAIN S-records, internal byte-sum, and
LZSS payload:

```bash
python3 tools/cdj_lab.py inspect-upd work/firmware/C2KNXS.UPD
```

The same command auto-detects the inferred single-segment MAIN container:

```bash
python3 tools/cdj_lab.py inspect-upd \
  work/firmware/C2KNXSM_v145_MAINONLY.UPD
```

Extract all segments plus the flat and decompressed MAIN images:

```bash
python3 tools/cdj_lab.py unpack-upd work/firmware/C2KNXS.UPD \
  --output work/unpacked/nxs
```

The command refuses structurally inconsistent containers, invalid S-record checksums,
overlapping S-record ranges, and MAIN payloads whose stored byte-sum does not verify.

## Inspect and render colour waveform data

List every ANLZ tag and summarize `PWV4`/`PWV5` metadata:

```bash
python3 tools/cdj_lab.py inspect-anlz work/samples/ANLZ0000.EXT
```

Render the fixed-width colour preview (`PWV4`) at an NXS-oriented width:

```bash
python3 tools/cdj_lab.py render-anlz work/samples/ANLZ0000.EXT \
  --tag PWV4 --width 480 --height 128 \
  --output work/renders/pwv4.png
```

Render the full-track colour detail (`PWV5`) into the same test canvas:

```bash
python3 tools/cdj_lab.py render-anlz work/samples/ANLZ0000.EXT \
  --tag PWV5 --width 480 --height 128 \
  --output work/renders/pwv5.png
```

`--tag auto` prefers `PWV4`, then falls back to `PWV5`.

## Evidence status

**Verified structurally from published reverse engineering:**

- ANLZ/PMAI and generic tag boundaries are big-endian.
- `PWV4` has a 24-byte tag header and six bytes per preview column.
- `PWV5` has a 24-byte tag header and two bytes per detail column.
- A `PWV5` entry packs 3-bit red, green, and blue components plus a 5-bit height.

**Verified locally with synthetic fixtures:**

- Strict S-record checksum and boundary handling.
- `.UPD` length parsing and the segment-specific CRC byte order.
- MAIN byte-sum discovery and LZSS decompression.
- `PWV4`/`PWV5` boundary parsing and dependency-free PNG output.

**Inferred and awaiting real sample comparison:**

- The visual mapping of `PWV4`'s luminance and two apparent height layers.
- Symmetric waveform placement in the simulated 480-pixel canvas.
- Any packet format for transporting colour columns from MAIN to GUI.

The current renderer is a test oracle for data plumbing, not a claim that its pixels
match the Blackfin renderer. A real `.EXT` now parses and renders; a rekordbox/NXS2
screenshot of the same track is the next visual positive control.

## Local firmware validation — 2026-08-08

User-supplied artifacts were copied into the ignored `work/firmware/` directory and
validated without modifying the originals:

| artifact | SHA-256 | offline result |
|---|---|---|
| stock `C2KNXS.UPD` | `b17c0f71…d81097` | all CRCs, S-records, byte-sum and LZSS verify |
| `C2KNXS_rebuilt.UPD` | `05c1398f…5db0f` | verifies; decompressed MAIN is byte-identical to stock |
| `C2KNXS_v145_test.UPD` | `9d838c9e…e04c3` | verifies; one decompressed byte changes `1.44` to `1.45` |
| `C2KNXSM_v145_MAINONLY.UPD` | `844d14d5…6d0d` | single length, CRC, S-records, byte-sum and LZSS verify |

The v1.45 decompressed change is at offset `0x743`, runtime address `0xA4000743`.
GUI, DRIVE and PANEL are byte-identical to stock. The MAIN-only payload is byte-for-byte
the same MAIN segment used by the full v1.45 image.

This verifies the MAIN-only artifact's internal consistency, **not** the inferred
single-segment container rule. That rule still needs comparison with a genuine Pioneer
per-processor update or a hardware test.

## Local ANLZ validation — 2026-08-08

A user-supplied `ANLZ0000.EXT` (SHA-256 `10de96c1…8c4d0`) validates as a 98,082-byte
PMAI file containing `PWV3`, `PWV4`, and `PWV5`. Both detail tags have 29,804 columns,
or 198.693 seconds at 150 columns per second. The lab produced:

```text
work/renders/ANLZ0000-PWV4.png
work/renders/ANLZ0000-PWV5.png
```

The next missing comparison artifact is a screenshot of this same track's RGB waveform
in rekordbox or on an NXS2.

## Reproduce the PWV3 static trace

Build the project-local GNU decoder once, then trace the stock decompressed image:

```bash
./scripts/build-sh4-binutils.sh
python3 tools/cdj_lab.py trace-main \
  work/unpacked/nxs-stock/MAIN_decomp.bin \
  --base 0xA4000000 --tag PWV3 \
  --objdump work/toolchain/sh-elf/bin/sh-elf-objdump \
  --anlz work/samples/ANLZ0000.EXT \
  --output work/analysis/pwv3
```

Outputs include `pwv3-trace.json`, `pwv3-trace.md`, the known comparison routine, all
three validators, the real PWV3 metadata handler, the database wave path, and the GUI
message constructors. These files are ignored because absolute paths and analysis of
the user-supplied firmware may be embedded in them.

## Ethernet hardware checkpoint

Use an isolated CDJ-to-PC link. Ethernet is behavioral correlation only: USB ANLZ
parsing and the internal MAIN→GUI transport may never appear on Pro DJ Link.

For each of two repetitions with the same track, start a fresh capture and record the
wall-clock time of these phases: boot/link, USB insertion, browse, track load, waveform
appearance, seek, and unload. Replace `en7` with the isolated adapter shown by
`ifconfig`:

```bash
mkdir -p work/analysis/ethernet
sudo tcpdump -i en7 -s 0 -w work/analysis/ethernet/repeat-1.pcap
# perform the phases, then stop tcpdump with Ctrl-C
sudo tcpdump -i en7 -s 0 -w work/analysis/ethernet/repeat-2.pcap
```

Scan both captures without changing them:

```bash
python3 tools/ethernet_trace.py \
  --anlz work/samples/ANLZ0000.EXT \
  --output work/analysis/ethernet/correlation.json \
  work/analysis/ethernet/repeat-1.pcap \
  work/analysis/ethernet/repeat-2.pcap
```

The scanner supports PCAP and PCAPNG and searches packet payloads for `PMAI`, `PWV3`,
`PWV4`, `PWV5`, the real PWV3 payload prefixes, and big/little-endian forms of 29,804
and its derived lengths. Save a short `TIMELINE.md` beside the captures with each phase
timestamp. A repeatable absence is a valid negative result and leaves the static trace
as the primary evidence. Serial and logic-analyser work are outside this checkpoint.

## Next experiment

Once real inputs are present:

1. Run the test suite and both inspection commands.
2. Render `PWV4` and compare it with rekordbox/NXS2 output for the same track.
3. Record field-value ranges and correct the inferred preview mapping.
4. Close the one static staging edge documented in FINDINGS §6b.
5. Capture and scan two time-correlated Ethernet repetitions.
6. Repeat the handler trace on NXS2 MAIN for `PWV5`, then compare its storage and GUI
   path before designing any patch.

References:

- [Deep Symmetry rekordbox export analysis](https://deepsymmetry.org/cratedigger/Analysis.pdf)
- [pyrekordbox ANLZ implementation](https://github.com/dylanljones/pyrekordbox)
