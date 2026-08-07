# SH-4 Cross-Toolchain Setup — CDJ-2000NXS

Purpose: be able to compile code that the CDJ's MAIN processor (Renesas SH7764,
SH-4A core, **little-endian**) will execute, and place it into free space in the
decompressed firmware image.

> These instructions were written from knowledge, not tested in this environment
> (no network access here). Expect to adapt version numbers and paths. The
> verification step in §5 is the part that actually matters — it proves the
> toolchain matches the firmware regardless of how you got there.

---

## 1. Why the Dreamcast toolchain

The Sega Dreamcast uses a **little-endian SH-4**, the same core family and the same
endianness as the CDJ's MAIN processor. The Dreamcast homebrew scene has maintained a
scripted, documented toolchain build for two decades. It is by far the shortest path
to a working `sh-elf-gcc`.

You do **not** need the Dreamcast libraries or KallistiOS itself — only the compiler,
assembler and linker it builds.

## 2. Recommended route — KallistiOS `dc-chain`

```bash
# prerequisites (Debian/Ubuntu)
sudo apt install build-essential texinfo libgmp-dev libmpfr-dev libmpc-dev \
                 libisl-dev wget patch bzip2 gawk libjpeg-dev libpng-dev

git clone https://github.com/KallistiOS/KallistiOS.git
cd KallistiOS/utils/dc-chain

cp config.mk.stable.sample config.mk
# Edit config.mk: you only need the SH build, so disable the ARM (AICA) target
# to halve the build time.

make          # expect 20-60 minutes
```

Result: `sh-elf-gcc`, `sh-elf-as`, `sh-elf-ld`, `sh-elf-objcopy`, `sh-elf-objdump`,
typically under `/opt/toolchains/dc/sh-elf/bin`. Add that to `PATH`.

## 3. Alternatives

**crosstool-ng** — general-purpose cross-toolchain builder, has `sh-elf` samples.
More configuration, more flexible, slower to get right.

**Distro packages** — some distributions ship `binutils-sh-elf` or
`gcc-sh4-linux-gnu`. The `sh4-linux-gnu` variants target Linux userspace, not bare
metal; usable for the assembler and objdump, but be careful about libc assumptions if
you compile C with them.

**Assembler only** — for the first "can I run my own code" test you don't strictly need
a C compiler. `sh-elf-as` plus `sh-elf-objcopy` is enough to assemble a handful of
instructions and extract raw bytes. If the full GCC build fights you, building just
binutils gets you moving.

## 4. Compiler flags that matter

```
-ml                  little-endian            <-- ESSENTIAL, wrong value = garbage
-m4-nofpu            SH-4, no FPU instructions
-ffreestanding       no hosted-environment assumptions
-nostdlib -nostartfiles
-fno-builtin
-Os                  optimise for size (space is not scarce, but keep patches small)
-fno-delayed-branch  see note below
```

**Endianness is the one that will silently ruin everything.** The firmware is
little-endian; SH toolchains commonly default to big-endian. Always pass `-ml`.

**`-m4-nofpu`** avoids emitting floating-point instructions. The SH7764 has an FPU, but
injected code that touches FP registers could clobber state the host firmware is
relying on. Keep FP out of patches unless there is a specific reason.

**Delay slots:** SH-4 branches have a delay slot — the instruction *after* a branch
executes before the branch takes effect. GCC handles this correctly, but it makes
hand-written assembly and hand-verification error-prone. `-fno-delayed-branch` produces
code that is easier to read and check by eye, at a small size cost. Worth it while
learning; drop it later.

Linking to a fixed address (see §6 for candidate addresses):

```bash
sh-elf-gcc -ml -m4-nofpu -ffreestanding -nostdlib -nostartfiles -fno-builtin -Os \
           -Wl,-Ttext=0xA40D57C4 -o patch.elf patch.c
sh-elf-objcopy -O binary patch.elf patch.bin
```

## 5. Verification — do this before writing any patch

The toolchain is only useful if it produces code matching the firmware's actual
conventions. There is a free, decisive test available: **disassemble the real firmware
with the new toolchain and compare against the known-good boot code.**

```bash
# extract the plain-code region of the decompressed/flat MAIN image
# (boot stub lives at 0x100-0x620 and 0x700-0xA20 in MAIN.bin, base 0xA0000000)
sh-elf-objdump -D -b binary -m sh4 -EL \
               --adjust-vma=0xA0000000 MAIN.bin | less
```

Compare the output against the documented boot sequence in the findings document:

| address | expected |
|---|---|
| `0xA0000100` | register-save prologue (`mov.l r9,@-r15` etc.) |
| `0xA0000298` | RAM test writing `0x55555555` / `0xAAAAAAAA` |
| `0xA00004FC` | DMA memcpy, programs registers at `0xFF608060` |
| `0xA0000700` | LZSS decompressor, ring buffer `0x0BFFD310` |

If `-EL` (little-endian) produces this and `-EB` produces nonsense, the toolchain and
the firmware agree, and the whole chain of analysis is independently corroborated by a
second, unrelated disassembler.

This also cross-checks `tools/sh4dis.py` — if the two disassemblers agree on the same
bytes, both are probably right.

## 6. Where injected code can live

Padding regions in the decompressed MAIN image (base `0xA4000000`), from the free-space
scan:

| address | size | fill |
|---|---|---|
| `0xA40D57C4` | 174,140 bytes | `0xFF` |
| `0xA43C55F8` | 109,060 bytes | `0xFF` |
| `0xA40604D0` | 25,248 bytes | `0xFF` |

Prefer the `0xFF` regions. `0xFF` is erased flash and almost certainly unused;
`0x00`-filled regions are often deliberately-cleared runtime buffers and may be written
to while the firmware runs.

There is far more space than any realistic patch needs, which means **patches can be
purely additive** — write new code into dead space and redirect one call site to it.
Nothing existing has to move, no addresses need fixing up, and the image size stays
identical. This is the safest possible shape for a firmware modification.

## 7. First milestone

Do not start with the feature. Start with the smallest thing that proves code runs:

1. Assemble a routine that does something harmless and observable, or even nothing at
   all (`rts` / `nop`).
2. Place it at `0xA40D57C4` in the decompressed image.
3. Redirect one non-critical call site to it, having it call the original afterwards.
4. Recompress, rebuild the `.UPD` (`tools/upd_build.py`), flash.
5. **Pass condition: the deck still boots normally.** Nothing visible needs to happen.

Surviving a boot with injected code present is the real hurdle. Everything after that
is ordinary software work.

## 8. Sequence reminder

This step only becomes relevant *after* the version-string test (`C2KNXS_v145_test.UPD`)
has been flashed successfully and the deck displays 1.45. That proves the
decompress → edit → recompress → checksum → flash → observe loop. Injecting code is the
next step up in difficulty, not a substitute for it.
