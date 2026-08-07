"""
LZSS *compressor* producing streams the CDJ-2000NXS boot ROM can decompress.

Must match the decoder read out of the firmware at 0xA0000700 exactly:
  N=4096 ring, F=18, THRESHOLD=2, ring pre-filled 0x20, r starts at N-F=0xFEE
  flags LSB-first, reloaded as (byte | 0xFF00); bit=1 -> literal, bit=0 -> match
  match encoded lo,hi:  pos = lo | ((hi & 0xF0) << 4)   len = (hi & 0x0F) + 3

Encoder strategy: model the decoder's ring exactly. A match of length L at output
distance d maps to ring position (r - d) & 0xFFF, because the ring holds the last
4096 output bytes with write pointer r. Overlapping matches (d < L) are legal and
produce run-length behaviour, since the decoder writes each byte as it copies.
"""

N = 4096
F = 18
THRESHOLD = 2
MIN_MATCH = THRESHOLD + 1   # 3
MAX_MATCH = F               # 18


def compress(data, max_candidates=64):
    out = bytearray()
    flag_pos = None
    flag_bit = 0
    flag_val = 0
    r = N - F
    i = 0
    n = len(data)
    index = {}          # 3-byte key -> list of positions (most recent last)

    def flush_start():
        nonlocal flag_pos, flag_bit, flag_val
        flag_pos = len(out)
        out.append(0)
        flag_val = 0
        flag_bit = 0

    def emit(is_literal, payload):
        nonlocal flag_bit, flag_val
        if flag_bit == 8 or flag_pos is None:
            out[flag_pos] = flag_val
            flush_start()
        if is_literal:
            flag_val |= (1 << flag_bit)
        flag_bit += 1
        out.extend(payload)

    flush_start()

    while i < n:
        best_len = 0
        best_d = 0
        if i + MIN_MATCH <= n:
            key = data[i:i+MIN_MATCH]
            cands = index.get(key)
            if cands:
                limit = min(MAX_MATCH, n - i)
                for j in reversed(cands[-max_candidates:]):
                    d = i - j
                    if d < 1 or d > N:
                        continue
                    # extend match (overlap allowed)
                    L = 0
                    while L < limit and data[j + L] == data[i + L]:
                        L += 1
                        if j + L >= i and L >= limit:
                            break
                    # allow overlap by repeating the pattern
                    if L < limit:
                        while L < limit and data[i - d + L] == data[i + L]:
                            L += 1
                    if L > best_len:
                        best_len = L
                        best_d = d
                        if L == limit:
                            break

        if best_len >= MIN_MATCH:
            pos = (r - best_d) & (N - 1)
            lo = pos & 0xFF
            hi = ((pos & 0xF00) >> 4) | (best_len - MIN_MATCH)
            emit(False, bytes((lo, hi)))
            for k in range(best_len):
                if i + k + MIN_MATCH <= n:
                    index.setdefault(data[i+k:i+k+MIN_MATCH], []).append(i + k)
            r = (r + best_len) & (N - 1)
            i += best_len
        else:
            emit(True, bytes((data[i],)))
            if i + MIN_MATCH <= n:
                index.setdefault(data[i:i+MIN_MATCH], []).append(i)
            r = (r + 1) & (N - 1)
            i += 1

    out[flag_pos] = flag_val
    return bytes(out)


def decompress(data, start=0, limit=None):
    """Reference decoder - identical to the firmware routine at 0xA0000700."""
    ring = bytearray(b' ' * N)
    r = N - F
    out = bytearray()
    p = start
    end = len(data) if limit is None else start + limit
    flags = 0
    while p < end:
        flags >>= 1
        if not (flags & 0x100):
            if p >= end:
                break
            flags = data[p] | 0xFF00
            p += 1
        if flags & 1:
            if p >= end:
                break
            c = data[p]; p += 1
            out.append(c); ring[r] = c; r = (r + 1) & (N - 1)
        else:
            if p + 1 >= end:
                break
            lo = data[p]; hi = data[p+1]; p += 2
            pos = lo | ((hi & 0xF0) << 4)
            ln = (hi & 0x0F) + MIN_MATCH
            for k in range(ln):
                c = ring[(pos + k) & (N - 1)]
                out.append(c); ring[r] = c; r = (r + 1) & (N - 1)
    return bytes(out)
