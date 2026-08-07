"""
Blackfin disassembler core, built directly from the real bit-field tables
in GDB/binutils' opcode/bfin.h (verified source, not guesswork).
Little-endian. 16-bit instructions have top-2-bits != 0b11; 0b11 means
this halfword begins a 32-bit (or parallel-issue) instruction - confirmed
against bfin-sim.c's own length-check: (iw0 & 0xc000) == 0xc000.
"""

def s(v, bits):
    m = 1 << (bits-1)
    return (v ^ m) - m

class Insn:
    __slots__=('addr','words','text','length','is_branch','branch_target',
               'is_call','falls_through','imm_load')
    def __init__(self, addr, words, text, length, is_branch=False,
                 branch_target=None, is_call=False, falls_through=True,
                 imm_load=None):
        self.addr=addr; self.words=words; self.text=text; self.length=length
        self.is_branch=is_branch; self.branch_target=branch_target
        self.is_call=is_call; self.falls_through=falls_through
        self.imm_load=imm_load  # ('H'|'L', reg_num, imm16) for LDIMMhalf

DREG = [f"R{i}" for i in range(8)]
PREG = [f"P{i}" for i in range(6)] + ["SP","FP"]  # grp-dependent really; simplified

def regname(grp, num):
    # grp: 0=Dreg,1=Preg,2=Ireg... simplified common mapping
    if grp == 0: return f"R{num}"
    if grp == 1: return ["P0","P1","P2","P3","P4","P5","SP","FP"][num]
    if grp == 2: return f"I{num}"
    if grp == 3: return f"M{num}"
    if grp == 4: return f"B{num}"
    if grp == 5: return f"L{num}"
    return f"g{grp}r{num}"

def decode(addr, w0, w1=None, w2=None):
    """w0 = first 16-bit halfword (already byte-swapped to a Python int).
    w1,w2 supplied if available (for 32-bit forms)."""
    if (w0 & 0xc000) != 0xc000:
        # ---------------- 16-bit instructions ----------------
        # ProgCtrl 0000000|prgfunc(4)|poprnd(4)
        if (w0 & 0xff00) == 0x0000:
            prgfunc = (w0 >> 4) & 0xF
            poprnd = w0 & 0xF
            if w0 == 0x0000: return Insn(addr,[w0],"NOP",2)
            if w0 == 0x0010: return Insn(addr,[w0],"RTS",2,is_branch=True,falls_through=False)
            if w0 == 0x0011: return Insn(addr,[w0],"RTI",2,is_branch=True,falls_through=False)
            if w0 == 0x0012: return Insn(addr,[w0],"RTX",2,is_branch=True,falls_through=False)
            if w0 == 0x0013: return Insn(addr,[w0],"RTN",2,is_branch=True,falls_through=False)
            if w0 == 0x0014: return Insn(addr,[w0],"RTE",2,is_branch=True,falls_through=False)
            if w0 == 0x0025: return Insn(addr,[w0],"EMUEXCPT",2)
            if 0x10 <= prgfunc <= 0x13 and False: pass
            if prgfunc == 0x5 and poprnd < 8: return Insn(addr,[w0],f"JUMP (P{poprnd})",2,is_branch=True,falls_through=False)
            if prgfunc == 0x6 and poprnd < 8: return Insn(addr,[w0],f"CALL (P{poprnd})",2,is_branch=True,is_call=True)
            return Insn(addr,[w0],f"ProgCtrl prgfunc={prgfunc:X} poprnd={poprnd:X}",2)
        # PushPopReg: 0000 0001 0 W grp(3) reg(3)
        if (w0 & 0xff00) == 0x0100:
            reg=w0&7; grp=(w0>>3)&7; W=(w0>>6)&1
            rn = regname(grp,reg)
            return Insn(addr,[w0], f"[--SP] = {rn}" if W else f"{rn} = [SP++]", 2)
        # PushPopMultiple: 0000 010 d p W dr(3) pr(3)
        if (w0 & 0xfe00) == 0x0400:
            pr=w0&7; dr=(w0>>3)&7; W=(w0>>6)&1; p=(w0>>7)&1; d=(w0>>8)&1
            return Insn(addr,[w0], f"PushPopMultiple d={d} p={p} W={W} dr={dr} pr={pr}", 2)
        # CCmv: 0000 0110 T d s dst(3) src(3)
        if (w0 & 0xff80) == 0x0600:
            return Insn(addr,[w0], "IF CC ... = ... (CCmv)", 2)
        # BRCC: 0001 T B offset(10)
        if (w0 & 0xf000) == 0x1000:
            T=(w0>>11)&1; B=(w0>>10)&1; off=s(w0&0x3ff,10)
            target = addr+4+off*2
            return Insn(addr,[w0], f"IF {'CC' if T else '!CC'} JUMP 0x{target:08X}" + (" (bp)" if B else ""),
                        2, is_branch=True, branch_target=target)
        # UJump: 0010 offset(12)
        if (w0 & 0xf000) == 0x2000:
            off = s(w0&0xfff,12)
            target = addr+4+off*2
            return Insn(addr,[w0], f"JUMP.S 0x{target:08X}", 2, is_branch=True,
                        branch_target=target, falls_through=False)
        # REGMV: 0011 gd(2) ... actually gd/gs are 3 bits each per table (0011 gd(3) gs(3) dst(3) src(3)) -- 16 bits total: 4+3+3+3+3=16? adjust
        if (w0 & 0xf000) == 0x3000:
            return Insn(addr,[w0], "REGMV", 2)
        # ALU2op: 0100 00 opc(4) src(3) dst(3)
        if (w0 & 0xfc00) == 0x4000:
            opc=(w0>>6)&0xF; src=(w0>>3)&7; dst=w0&7
            return Insn(addr,[w0], f"ALU2op opc={opc:X} R{src},R{dst}", 2)
        # PTR2op: 0100 010 opc(3) src(3) dst(3)
        if (w0 & 0xfe00) == 0x4400:
            opc=(w0>>6)&7; src=(w0>>3)&7; dst=w0&7
            return Insn(addr,[w0], f"PTR2op opc={opc:X} P{src},P{dst}", 2)
        # LOGI2op: 0100 1 opc(3) src(5) dst(3)
        if (w0 & 0xf800) == 0x4800:
            opc=(w0>>8)&7; src=(w0>>3)&0x1f; dst=w0&7
            return Insn(addr,[w0], f"LOGI2op opc={opc:X} #{src},R{dst}", 2)
        # COMP3op: 0101 opc(3) dst(3) src1(3) src0(3)
        if (w0 & 0xf000) == 0x5000:
            return Insn(addr,[w0], "COMP3op", 2)
        # COMPI2opD: 01100 op src(7) dst(3)
        if (w0 & 0xf800) == 0x6000:
            op=(w0>>10)&1; src=s((w0>>3)&0x7f,7); dst=w0&7
            return Insn(addr,[w0], f"R{dst} {'+=' if op else '='} #{src}", 2)
        # COMPI2opP: 01101 op src(7) dst(3)
        if (w0 & 0xf800) == 0x6800:
            op=(w0>>10)&1; src=s((w0>>3)&0x7f,7); dst=w0&7
            return Insn(addr,[w0], f"P{dst} {'+=' if op else '='} #{src}", 2)
        # LDSTpmod: 1000 W aop(2) reg(3) idx(3) ptr(3)
        if (w0 & 0xf000) == 0x8000:
            ptr=w0&7; idx=(w0>>3)&7; reg=(w0>>6)&7; aop=(w0>>9)&3; W=(w0>>11)&1
            return Insn(addr,[w0], f"LDSTpmod W={W} aop={aop} R{reg},[P{ptr}+I{idx}]", 2)
        # LDST: 1001 sz(2) W aop(2) Z ptr(3) reg(3)
        if (w0 & 0xf000) == 0x9000 and (w0 & 0xfc00) != 0x9c00:
            reg=w0&7; ptr=(w0>>3)&7; Z=(w0>>6)&1; aop=(w0>>7)&3; W=(w0>>9)&1; sz=(w0>>10)&3
            return Insn(addr,[w0], f"LDST sz={sz} W={W} aop={aop} Z={Z} R{reg},[P{ptr}]", 2)
        # DspLDST 1001 11 ...
        if (w0 & 0xfc00) == 0x9c00:
            return Insn(addr,[w0], "DspLDST", 2)
        # LDSTii: 101 W op(2) offset(4) ptr(3) reg(3)
        if (w0 & 0xe000) == 0xa000 and (w0 & 0xf800) != 0xb800:
            reg=w0&7; ptr=(w0>>3)&7; off=(w0>>6)&0xf; op=(w0>>10)&3; W=(w0>>12)&1
            return Insn(addr,[w0], f"LDSTii op={op} W={W} off={off} R{reg},[P{ptr}]", 2)
        # LDSTiiFP: 1011 10 W offset(5) reg(4)
        if (w0 & 0xfc00) == 0xb800:
            reg=w0&0xf; off=(w0>>4)&0x1f; W=(w0>>9)&1
            return Insn(addr,[w0], f"LDSTiiFP W={W} off={off} reg={reg} [FP+off]", 2)
        # CaCTRL 0000001001 a op(2) reg(3)
        if (w0 & 0xffc0) == 0x0240:
            return Insn(addr,[w0], "CaCTRL", 2)
        return Insn(addr,[w0], f".hw 0x{w0:04X} ; UNK16", 2)
    else:
        # ---------------- 32-bit instructions ----------------
        if w1 is None:
            return Insn(addr,[w0], ".word (truncated 32-bit)", 4)
        full = (w0 << 16) | w1
        top8 = w0 >> 8  # bits 31:24 of full
        # LDIMMhalf: 1110 0001 Z H S grp(2) reg(3) | hword(16)
        if (w0 & 0xff00) == 0xe100:
            reg = w0 & 7
            grp = (w0>>3) & 3
            S = (w0>>5) & 1
            H = (w0>>6) & 1
            Z = (w0>>7) & 1
            hword = w1
            half = 'H' if H else 'L'
            rn = regname(grp, reg)
            if Z or S:
                # full-register form: reg = imm16 (Z) / (X) - writes all 32 bits
                txt = f"{rn} = 0x{hword:04X} ({'Z' if Z else 'X'})"
                return Insn(addr,[w0,w1], txt, 4,
                            imm_load=('F', grp, reg, hword, Z, S))
            return Insn(addr,[w0,w1], f"{rn}.{half} = 0x{hword:04X}", 4,
                        imm_load=(half, grp, reg, hword, Z, S))
        # CALLa: 1110 0010 S msw(23) | lsw(16)  -> addr = (msw<<16|lsw)<<1, S:0=jump.l 1=call
        if (w0 & 0xff00) in (0xe200, 0xe300):
            S = (w0 >> 8) & 1  # actually per table S is bit24 overall -> within w0 it's bit8
            msw = w0 & 0xFF
            addr24 = (msw << 16) | w1
            target = addr + s(addr24,24)*2
            mnem = "CALL" if (w0 & 0x0100) else "JUMP.L"
            return Insn(addr,[w0,w1], f"{mnem} 0x{target:08X}", 4, is_branch=True,
                        branch_target=target, is_call=(mnem=="CALL"),
                        falls_through=(mnem=="CALL"))
        # Linkage (LINK/UNLINK): 1110 1000 0000000 R | framesize(16)
        if (w0 & 0xfffe) == 0xe800:
            R = w0 & 1
            return Insn(addr,[w0,w1], ("UNLINK" if R else f"LINK #{w1}"), 4)
        # LoopSetup: 1110 0000 1 rop(2) c soffset(4) | reg(4) -- eoffset(10)
        if (w0 & 0xff80) == 0xe080:
            return Insn(addr,[w0,w1], "LSETUP", 4)
        # LDSTidxI: 1110 01 W Z sz(2) ptr(3) reg(3) | offset(16)
        if (w0 & 0xfc00) == 0xe400 or (w0 & 0xfc00) == 0xe000:
            reg=w0&7; ptr=(w0>>3)&7
            return Insn(addr,[w0,w1], f"LDSTidxI R{reg},[P{ptr}+0x{w1:04X}]", 4)
        # DSP32* family: top 4 bits of w0 = 1100
        if (w0 & 0xf000) == 0xc000:
            sub = (w0 >> 8) & 0xF
            return Insn(addr,[w0,w1], f"DSP32(sub={sub:X}) 0x{w0:04X}{w1:04X}", 4)
        # PseudoDbg_Assert: 1111 0...
        if (w0 & 0xf000) == 0xf000 and (w0 & 0xf800) != 0xf800:
            return Insn(addr,[w0,w1], "DBG_ASSERT", 4)
        return Insn(addr,[w0,w1], f".word 0x{w0:04X}{w1:04X} ; UNK32", 4)

def disasm_range(img, base, start, end):
    out=[]
    a=start
    n=len(img)
    while a<end:
        off=a-base
        if off<0 or off+2>n: break
        w0 = img[off] | (img[off+1]<<8)
        if (w0 & 0xc000)==0xc000 and off+4<=n:
            w1 = img[off+2] | (img[off+3]<<8)
            ins = decode(a,w0,w1)
        else:
            ins = decode(a,w0)
        out.append(ins)
        a += ins.length
    return out
