"""
dataflow.py -- lightweight intra-function constant/pointer propagation for Blackfin.

Motivation
----------
Earlier scans could only see accesses where code re-materialised a literal
address inline (`Px.H = hi; Px.L = lo; ... [Px] = val`). Real compiled code
loads a pointer once and then reuses it via register copies, stack spills and
reloads, or small +/- offsets. Those accesses were invisible.

This module does a small abstract interpretation over a function's instructions:
  - tracks each P/R register as either UNKNOWN or a known 32-bit constant
  - handles LDIMMhalf (H/L pair) constant materialisation
  - handles COMPI2opP / COMPI2opD (`P += imm`, `P = imm`, `R += imm`, `R = imm`)
  - handles RegMv (register-to-register copies) -- decoded properly here, since
    bfindis.py only stubs it out
  - handles stack spill/reload through the frame pointer (LDSTiiFP) so a pointer
    parked on the stack and reloaded later is still tracked
  - records every load/store whose *effective address* is a known constant

It is deliberately conservative: anything it can't prove becomes UNKNOWN rather
than guessed. False negatives are acceptable; false positives are not, because
the whole point is to stop chasing coincidences.

Known limitation: this is straight-line + simple-merge only. At a branch target
reached from multiple paths, conflicting values are merged to UNKNOWN. It does
not iterate loops to a fixpoint. Good enough to answer "who touches address X",
which is what we need.
"""

import struct

UNKNOWN = None


def s7(v):
    return v - 128 if v & 0x40 else v


def decode_regmv(w0):
    """RegMv: 0011 gd(3) gs(3) dst(3) src(3) -- bfindis.py stubs this; decode properly.
    Returns (dst_grp, dst_num, src_grp, src_num)."""
    src = w0 & 7
    dst = (w0 >> 3) & 7
    gs = (w0 >> 6) & 7
    gd = (w0 >> 9) & 7
    return gd, dst, gs, src


class State:
    """Abstract register/stack state. Values are ints (known) or None (unknown)."""

    __slots__ = ('regs', 'stack')

    def __init__(self):
        # keyed by (grp, num); grp 0 = Dreg (R0-R7), grp 1 = Preg (P0-P5,SP,FP)
        self.regs = {}
        # keyed by frame-pointer offset -> value
        self.stack = {}

    def copy(self):
        s = State()
        s.regs = dict(self.regs)
        s.stack = dict(self.stack)
        return s

    def get(self, key):
        return self.regs.get(key, UNKNOWN)

    def set(self, key, val):
        if val is UNKNOWN:
            self.regs.pop(key, None)
        else:
            self.regs[key] = val & 0xFFFFFFFF

    def merge(self, other):
        """Keep only values both states agree on."""
        for k in list(self.regs):
            if other.regs.get(k, UNKNOWN) != self.regs[k]:
                self.regs.pop(k, None)
        for k in list(self.stack):
            if other.stack.get(k, UNKNOWN) != self.stack[k]:
                self.stack.pop(k, None)


class Access:
    __slots__ = ('addr', 'target', 'is_write', 'size', 'text')

    def __init__(self, addr, target, is_write, size, text):
        self.addr = addr
        self.target = target
        self.is_write = is_write
        self.size = size
        self.text = text

    def __repr__(self):
        kind = 'W' if self.is_write else 'R'
        return f"<{kind}{self.size*8} @0x{self.addr:08X} -> 0x{self.target:08X}>"


def analyse(insns, verbose=False):
    """Run propagation over a linear list of decoded Insn objects (one function).

    Returns list[Access] -- every load/store resolved to a concrete address.
    """
    st = State()
    accesses = []
    pending_hi = {}

    # Pre-index instruction addresses so we can merge at branch targets.
    # (Simple approach: reset state at any address that is a branch target,
    # since we can't prove what path reached it.)
    branch_targets = set()
    for ins in insns:
        if ins.is_branch and ins.branch_target is not None:
            branch_targets.add(ins.branch_target)

    for ins in insns:
        if ins.addr in branch_targets:
            # conservative: multiple predecessors, drop everything we can't prove
            st = State()
            pending_hi.clear()

        w0 = ins.words[0]

        # ---- constant materialisation: LDIMMhalf ----
        # Blackfin builds 32-bit constants from two halves, and the compiler emits
        # them in EITHER order (.L then .H is common). Track halves independently
        # with a known-mask instead of assuming an order.
        if ins.imm_load:
            half, grp, reg, val = ins.imm_load[:4]
            key = (grp, reg)
            if half == 'F':
                # reg = imm16 (Z)/(X): writes the whole register
                Z = ins.imm_load[4] if len(ins.imm_load) > 4 else 1
                full = val if Z else (val - 0x10000 if val & 0x8000 else val)
                st.set(key, full & 0xFFFFFFFF)
                pending_hi.pop(key, None)
                continue
            lo, hi, mask = pending_hi.get(key, (0, 0, 0))
            if half == 'H':
                hi = val
                mask |= 0b10
            else:
                lo = val
                mask |= 0b01
            if mask == 0b11:
                st.set(key, (hi << 16) | lo)
                pending_hi.pop(key, None)
            else:
                pending_hi[key] = (lo, hi, mask)
                st.set(key, UNKNOWN)
            continue

        # ---- P += imm / P = imm  (COMPI2opP, 0x6800) ----
        if (w0 & 0xF800) == 0x6800:
            op = (w0 >> 10) & 1
            imm = s7((w0 >> 3) & 0x7F)
            dst = w0 & 7
            key = (1, dst)
            if op:  # +=
                cur = st.get(key)
                st.set(key, UNKNOWN if cur is UNKNOWN else cur + imm)
            else:   # =
                st.set(key, imm)
            continue

        # ---- R += imm / R = imm  (COMPI2opD, 0x6000) ----
        if (w0 & 0xF800) == 0x6000:
            op = (w0 >> 10) & 1
            imm = s7((w0 >> 3) & 0x7F)
            dst = w0 & 7
            key = (0, dst)
            if op:
                cur = st.get(key)
                st.set(key, UNKNOWN if cur is UNKNOWN else cur + imm)
            else:
                st.set(key, imm)
            continue

        # ---- register-to-register move (RegMv, 0x3000) ----
        if (w0 & 0xF000) == 0x3000:
            gd, dst, gs, src = decode_regmv(w0)
            st.set((gd, dst), st.get((gs, src)))
            continue

        # ---- stack spill / reload via FP (LDSTiiFP, 0xB800) ----
        if (w0 & 0xFC00) == 0xB800:
            reg = w0 & 0xF
            off = (w0 >> 4) & 0x1F
            W = (w0 >> 9) & 1
            # reg field here indexes D then P registers
            grp = 0 if reg < 8 else 1
            num = reg & 7
            if W:  # store to stack
                v = st.get((grp, num))
                if v is UNKNOWN:
                    st.stack.pop(off, None)
                else:
                    st.stack[off] = v
            else:  # load from stack
                st.set((grp, num), st.stack.get(off, UNKNOWN))
            continue

        # ---- loads/stores through a pointer register ----
        # LDST (0x9000, excluding DspLDST 0x9C00): ptr in bits 3-5
        if (w0 & 0xF000) == 0x9000 and (w0 & 0xFC00) != 0x9C00:
            ptr = (w0 >> 3) & 7
            W = (w0 >> 9) & 1
            sz = (w0 >> 10) & 3
            size = {0: 4, 1: 2, 2: 1}.get(sz, 4)
            base = st.get((1, ptr))
            if base is not UNKNOWN:
                accesses.append(Access(ins.addr, base, bool(W), size, ins.text))
            # a load overwrites its destination reg with unknown data
            if not W:
                st.set((0, w0 & 7), UNKNOWN)
            continue

        # LDSTii (0xA000-0xB7FF): ptr bits 3-5, scaled offset bits 6-9
        if (w0 & 0xE000) == 0xA000 and (w0 & 0xF800) != 0xB800:
            ptr = (w0 >> 3) & 7
            off = (w0 >> 6) & 0xF
            op = (w0 >> 10) & 3
            W = (w0 >> 12) & 1
            scale = {0: 4, 1: 2, 2: 1, 3: 2}.get(op, 4)
            base = st.get((1, ptr))
            if base is not UNKNOWN:
                accesses.append(
                    Access(ins.addr, base + off * scale, bool(W), scale, ins.text))
            if not W:
                st.set((0, w0 & 7), UNKNOWN)
            continue

        # LDSTpmod (0x8000): ptr bits 0-2
        if (w0 & 0xF000) == 0x8000:
            ptr = w0 & 7
            W = (w0 >> 11) & 1
            base = st.get((1, ptr))
            if base is not UNKNOWN:
                accesses.append(Access(ins.addr, base, bool(W), 2, ins.text))
            continue

        # ---- calls clobber caller-saved registers ----
        if ins.is_call:
            for r in range(4):
                st.set((0, r), UNKNOWN)
            for p in range(3):
                st.set((1, p), UNKNOWN)
            continue

        # ---- anything we don't model: invalidate its apparent destination ----
        # ALU2op / LOGI2op / COMP3op / PTR2op all write a register we can't track
        if (w0 & 0xFC00) == 0x4000 or (w0 & 0xF800) == 0x4800 or (w0 & 0xF000) == 0x5000:
            st.set((0, w0 & 7), UNKNOWN)
        elif (w0 & 0xFE00) == 0x4400:
            st.set((1, w0 & 7), UNKNOWN)

    return accesses


def find_functions(insns):
    """Split a linear instruction list into functions on LINK/RTS boundaries.
    Returns list of (start_addr, [insns])."""
    funcs = []
    cur = []
    for ins in insns:
        if ins.text.startswith('LINK') and cur:
            funcs.append((cur[0].addr, cur))
            cur = [ins]
        else:
            cur.append(ins)
        if ins.text == 'RTS' and cur:
            funcs.append((cur[0].addr, cur))
            cur = []
    if cur:
        funcs.append((cur[0].addr, cur))
    return funcs
