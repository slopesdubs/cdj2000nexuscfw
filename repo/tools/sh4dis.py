"""
Minimal-but-real SH-4 (big-endian) disassembler.
Covers the vast majority of integer/control instructions used in
application-level C code. FPU vector ops (FIPR/FSCA/etc.) and a handful
of rare privileged ops are decoded as UNK with raw hex - fine for triage,
flag if we land on one of those addresses and need it filled in.

Encoding reference: standard SH-4 16-bit fixed instruction formats.
"""

def s8(v):
    return v - 256 if v & 0x80 else v

def s12(v):
    return v - 4096 if v & 0x800 else v

class Insn:
    __slots__ = ('addr','word','text','is_branch','branch_target','is_call',
                 'is_cond_branch','literal_ref','falls_through')
    def __init__(self, addr, word, text, is_branch=False, branch_target=None,
                 is_call=False, is_cond_branch=False, literal_ref=None,
                 falls_through=True):
        self.addr=addr; self.word=word; self.text=text
        self.is_branch=is_branch; self.branch_target=branch_target
        self.is_call=is_call; self.is_cond_branch=is_cond_branch
        self.literal_ref=literal_ref  # address a MOV.L/MOV.W @(disp,PC) reads from
        self.falls_through=falls_through

def decode(addr, word):
    """word: 16-bit instruction. addr: address of this instruction (SH-4 PC space)."""
    n = (word >> 8) & 0xF
    m = (word >> 4) & 0xF
    op4 = word >> 12
    low4 = word & 0xF
    low8 = word & 0xFF

    def R(x): return f"R{x}"

    # --- literal loads: MOV.L @(disp,PC),Rn ---
    # NOTE: this target CPU config stores 16-bit instruction words AND 32-bit
    # literal-pool data little-endian (confirmed empirically against the real
    # reset vector - despite SH-4 supporting big-endian, this board is wired LE).
    if op4 == 0xD:
        d = low8
        target = ((addr + 4) & ~3) + d*4
        return Insn(addr, word, f"MOV.L @(0x{d:02X},PC),{R(n)}    ; -> [0x{target:08X}]",
                    literal_ref=('L', target))
    if op4 == 0x9:
        d = low8
        target = ((addr + 4) & ~3) + d*2
        return Insn(addr, word, f"MOV.W @(0x{d:02X},PC),{R(n)}    ; -> [0x{target:08X}]",
                    literal_ref=('W', target))
    if word == 0xC700 or (op4 == 0xC and n == 7):
        pass  # handled below generically (MOVA)

    # --- 0xC7xx MOVA @(disp,PC),R0 ---
    if (word & 0xFF00) == 0xC700:
        d = low8
        target = ((addr + 4) & ~3) + d*4
        return Insn(addr, word, f"MOVA @(0x{d:02X},PC),R0    ; -> 0x{target:08X}",
                    literal_ref=('A', target))

    # --- branch instructions ---
    if op4 == 0xA:  # BRA
        d = s12(word & 0xFFF)
        target = addr + 4 + d*2
        return Insn(addr, word, f"BRA 0x{target:08X}", is_branch=True,
                     branch_target=target, falls_through=False)
    if op4 == 0xB:  # BSR
        d = s12(word & 0xFFF)
        target = addr + 4 + d*2
        return Insn(addr, word, f"BSR 0x{target:08X}", is_branch=True,
                     branch_target=target, is_call=True)
    if (word & 0xFF00) == 0x8B00:  # BF
        d = s8(low8)
        target = addr + 4 + d*2
        return Insn(addr, word, f"BF 0x{target:08X}", is_branch=True,
                     branch_target=target, is_cond_branch=True)
    if (word & 0xFF00) == 0x8F00:  # BF/S
        d = s8(low8)
        target = addr + 4 + d*2
        return Insn(addr, word, f"BF/S 0x{target:08X}", is_branch=True,
                     branch_target=target, is_cond_branch=True)
    if (word & 0xFF00) == 0x8900:  # BT
        d = s8(low8)
        target = addr + 4 + d*2
        return Insn(addr, word, f"BT 0x{target:08X}", is_branch=True,
                     branch_target=target, is_cond_branch=True)
    if (word & 0xFF00) == 0x8D00:  # BT/S
        d = s8(low8)
        target = addr + 4 + d*2
        return Insn(addr, word, f"BT/S 0x{target:08X}", is_branch=True,
                     branch_target=target, is_cond_branch=True)
    if (word & 0xF0FF) == 0x0023:  # BRAF Rn
        return Insn(addr, word, f"BRAF {R(n)}", is_branch=True, falls_through=False)
    if (word & 0xF0FF) == 0x0003:  # BSRF Rn
        return Insn(addr, word, f"BSRF {R(n)}", is_branch=True, is_call=True)
    if (word & 0xF0FF) == 0x402B:  # JMP @Rn
        return Insn(addr, word, f"JMP @{R(n)}", is_branch=True, falls_through=False)
    if (word & 0xF0FF) == 0x400B:  # JSR @Rn
        return Insn(addr, word, f"JSR @{R(n)}", is_branch=True, is_call=True)
    if word == 0x000B:
        return Insn(addr, word, "RTS", is_branch=True, falls_through=False)
    if word == 0x002B:
        return Insn(addr, word, "RTE", is_branch=True, falls_through=False)

    # --- misc singletons ---
    singles = {
        0x0009:"NOP", 0x0028:"CLRMAC", 0x0048:"CLRS", 0x0008:"CLRT",
        0x0018:"SETT", 0x0058:"SETS", 0x0019:"DIV0U", 0x001B:"SLEEP",
        0x0038:"LDTLB",
    }
    if word in singles:
        return Insn(addr, word, singles[word])

    # --- n-only ---
    if (word & 0xF0FF) == 0x4015: return Insn(addr, word, f"CMP/PL {R(n)}")
    if (word & 0xF0FF) == 0x4011: return Insn(addr, word, f"CMP/PZ {R(n)}")
    if (word & 0xF0FF) == 0x4010: return Insn(addr, word, f"DT {R(n)}")
    if (word & 0xF0FF) == 0x4004: return Insn(addr, word, f"ROTL {R(n)}")
    if (word & 0xF0FF) == 0x4005: return Insn(addr, word, f"ROTR {R(n)}")
    if (word & 0xF0FF) == 0x4024: return Insn(addr, word, f"ROTCL {R(n)}")
    if (word & 0xF0FF) == 0x4025: return Insn(addr, word, f"ROTCR {R(n)}")
    if (word & 0xF0FF) == 0x4020: return Insn(addr, word, f"SHAL {R(n)}")
    if (word & 0xF0FF) == 0x4021: return Insn(addr, word, f"SHAR {R(n)}")
    if (word & 0xF0FF) == 0x4000: return Insn(addr, word, f"SHLL {R(n)}")
    if (word & 0xF0FF) == 0x4008: return Insn(addr, word, f"SHLL2 {R(n)}")
    if (word & 0xF0FF) == 0x4018: return Insn(addr, word, f"SHLL8 {R(n)}")
    if (word & 0xF0FF) == 0x4028: return Insn(addr, word, f"SHLL16 {R(n)}")
    if (word & 0xF0FF) == 0x4001: return Insn(addr, word, f"SHLR {R(n)}")
    if (word & 0xF0FF) == 0x4009: return Insn(addr, word, f"SHLR2 {R(n)}")
    if (word & 0xF0FF) == 0x4019: return Insn(addr, word, f"SHLR8 {R(n)}")
    if (word & 0xF0FF) == 0x4029: return Insn(addr, word, f"SHLR16 {R(n)}")
    if (word & 0xF0FF) == 0x0029: return Insn(addr, word, f"MOVT {R(n)}")
    if (word & 0xF0FF) == 0x401B: return Insn(addr, word, f"TAS.B @{R(n)}")
    if (word & 0xF0FF) == 0x00C3: return Insn(addr, word, f"MOVCA.L R0,@{R(n)}")
    if (word & 0xF0FF) == 0x0093: return Insn(addr, word, f"OCBI @{R(n)}")
    if (word & 0xF0FF) == 0x00A3: return Insn(addr, word, f"OCBP @{R(n)}")
    if (word & 0xF0FF) == 0x00B3: return Insn(addr, word, f"OCBWB @{R(n)}")
    if (word & 0xF0FF) == 0x0083: return Insn(addr, word, f"PREF @{R(n)}")
    if (word & 0xF0FF) == 0x400E: return Insn(addr, word, f"LDC {R(n)},SR")
    if (word & 0xF0FF) == 0x401E: return Insn(addr, word, f"LDC {R(n)},GBR")
    if (word & 0xF0FF) == 0x402E: return Insn(addr, word, f"LDC {R(n)},VBR")
    if (word & 0xF0FF) == 0x403E: return Insn(addr, word, f"LDC {R(n)},SSR")
    if (word & 0xF0FF) == 0x404E: return Insn(addr, word, f"LDC {R(n)},SPC")
    if (word & 0xF0FF) == 0x400A: return Insn(addr, word, f"LDS {R(n)},MACH")
    if (word & 0xF0FF) == 0x401A: return Insn(addr, word, f"LDS {R(n)},MACL")
    if (word & 0xF0FF) == 0x402A: return Insn(addr, word, f"LDS {R(n)},PR")
    if (word & 0xF0FF) == 0x4007: return Insn(addr, word, f"LDC.L @{R(n)}+,SR")
    if (word & 0xF0FF) == 0x4006: return Insn(addr, word, f"LDS.L @{R(n)}+,MACH")
    if (word & 0xF0FF) == 0x0002: return Insn(addr, word, f"STC SR,{R(n)}")
    if (word & 0xF0FF) == 0x0012: return Insn(addr, word, f"STC GBR,{R(n)}")
    if (word & 0xF0FF) == 0x0022: return Insn(addr, word, f"STC VBR,{R(n)}")
    if (word & 0xF0FF) == 0x000A: return Insn(addr, word, f"STS MACH,{R(n)}")
    if (word & 0xF0FF) == 0x001A: return Insn(addr, word, f"STS MACL,{R(n)}")
    if (word & 0xF0FF) == 0x002A: return Insn(addr, word, f"STS PR,{R(n)}")
    if (word & 0xF0FF) == 0x4002: return Insn(addr, word, f"STS.L MACH,@-{R(n)}")

    # --- nm-format (two regs) ---
    nm = {
        0x300C:"ADD",0x300E:"ADDC",0x300F:"ADDV",0x3000:"CMP/EQ",0x3002:"CMP/HS",
        0x3003:"CMP/GE",0x3006:"CMP/HI",0x3007:"CMP/GT",0x3004:"DIV1",
        0x300D:"DMULS.L",0x3005:"DMULU.L",0x3008:"SUB",0x300A:"SUBC",0x300B:"SUBV",
        0x2009:"AND",0x200B:"OR",0x200A:"XOR",0x2008:"TST",0x200C:"CMP/STR",
        0x2007:"DIV0S",0x600B:"NEG",0x600A:"NEGC",0x6007:"NOT",0x6003:"MOV",
        0x6000:"MOV.B",0x6001:"MOV.W",0x6002:"MOV.L",0x6004:"MOV.B @Rm+,",
        0x6008:"SWAP.B",0x6009:"SWAP.W",0x200D:"XTRCT",0x200F:"MULS.W",
        0x200E:"MULU.W",0x600E:"EXTS.B",0x600F:"EXTS.W",0x600C:"EXTU.B",
        0x600D:"EXTU.W",0x0007:"MUL.L",0x400C:"SHAD",0x400D:"SHLD",
        0x2000:"MOV.B",0x2001:"MOV.W",0x2002:"MOV.L",
        0x2004:"MOV.B",0x2005:"MOV.W",0x2006:"MOV.L",
        0x6005:"MOV.W",0x6006:"MOV.L",
        0x0004:"MOV.B",0x0005:"MOV.W",0x0006:"MOV.L",
        0x000C:"MOV.B",0x000D:"MOV.W",0x000E:"MOV.L",
    }
    key = word & 0xF00F
    if key in nm:
        mnem = nm[key]
        # crude but workable operand rendering per common cases
        if key in (0x6000,0x6001,0x6002): txt=f"{mnem} @{R(m)},{R(n)}"
        elif key in (0x6004,0x6005,0x6006): txt=f"{mnem} @{R(m)}+,{R(n)}"
        elif key in (0x2000,0x2001,0x2002): txt=f"{mnem} {R(m)},@{R(n)}"
        elif key in (0x2004,0x2005,0x2006): txt=f"{mnem} {R(m)},@-{R(n)}"
        elif key in (0x0004,0x0005,0x0006): txt=f"{mnem} {R(m)},@(R0,{R(n)})"
        elif key in (0x000C,0x000D,0x000E): txt=f"{mnem} @(R0,{R(m)}),{R(n)}"
        else: txt=f"{mnem} {R(m)},{R(n)}"
        return Insn(addr, word, txt)

    # --- i-format (imm + reg) ---
    if op4 == 0x7:
        return Insn(addr, word, f"ADD #{s8(low8)},{R(n)}")
    if op4 == 0xE:
        return Insn(addr, word, f"MOV #{s8(low8)},{R(n)}")
    if (word & 0xFF00) == 0x8800: return Insn(addr, word, f"CMP/EQ #{s8(low8)},R0")
    if (word & 0xFF00) == 0xC900: return Insn(addr, word, f"AND #0x{low8:02X},R0")
    if (word & 0xFF00) == 0xCB00: return Insn(addr, word, f"OR #0x{low8:02X},R0")
    if (word & 0xFF00) == 0xC800: return Insn(addr, word, f"TST #0x{low8:02X},R0")
    if (word & 0xFF00) == 0xCA00: return Insn(addr, word, f"XOR #0x{low8:02X},R0")
    if (word & 0xFF00) == 0xC300: return Insn(addr, word, f"TRAPA #0x{low8:02X}")

    # --- disp+reg forms ---
    if op4 == 0x1:
        return Insn(addr, word, f"MOV.L {R(m)},@(0x{low4*4:X},{R(n)})")
    if op4 == 0x5:
        return Insn(addr, word, f"MOV.L @(0x{low4*4:X},{R(m)}),{R(n)}")
    if (word & 0xFF00) == 0x8000:
        return Insn(addr, word, f"MOV.B R0,@(0x{low4:X},{R(n)})")
    if (word & 0xFF00) == 0x8100:
        return Insn(addr, word, f"MOV.W R0,@(0x{low4*2:X},{R(n)})")
    if (word & 0xFF00) == 0x8400:
        return Insn(addr, word, f"MOV.B @(0x{low4:X},{R(m)}),R0")
    if (word & 0xFF00) == 0x8500:
        return Insn(addr, word, f"MOV.W @(0x{low4*2:X},{R(m)}),R0")
    if (word & 0xFF00) == 0xC000: return Insn(addr, word, f"MOV.B R0,@(0x{low8:X},GBR)")
    if (word & 0xFF00) == 0xC100: return Insn(addr, word, f"MOV.W R0,@(0x{low8*2:X},GBR)")
    if (word & 0xFF00) == 0xC200: return Insn(addr, word, f"MOV.L R0,@(0x{low8*4:X},GBR)")
    if (word & 0xFF00) == 0xC400: return Insn(addr, word, f"MOV.B @(0x{low8:X},GBR),R0")
    if (word & 0xFF00) == 0xC500: return Insn(addr, word, f"MOV.W @(0x{low8*2:X},GBR),R0")
    if (word & 0xFF00) == 0xC600: return Insn(addr, word, f"MOV.L @(0x{low8*4:X},GBR),R0")

    if (word & 0xF0FF) == 0x4023: pass  # BRAF handled above

    # FPU / unknown fallback
    if op4 == 0xF:
        return Insn(addr, word, f"FPU_OP .word 0x{word:04X}")

    return Insn(addr, word, f".word 0x{word:04X}  ; UNK")


def disasm_range(img, base, start, end):
    out = []
    a = start
    while a < end:
        off = a - base
        if off < 0 or off+2 > len(img):
            break
        word = img[off] | (img[off+1] << 8)   # little-endian
        ins = decode(a, word)
        out.append(ins)
        a += 2
    return out

def read_word(img, base, addr):
    off = addr - base
    return img[off] | (img[off+1] << 8)

def read_u32(img, base, addr):
    off = addr - base
    return img[off] | (img[off+1]<<8) | (img[off+2]<<16) | (img[off+3]<<24)
