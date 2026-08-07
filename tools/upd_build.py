"""
Rebuild a CDJ-2000NXS .UPD from parsed parts.

Verified container rules (see notes):
  .UPD  = ASCII "<len>\r\n" x4  then the four segments concatenated
  MAIN/DRIV/PANL segment = 32-byte ASCII header
                           + S0 record
                           + S2 records (24-byte count => 32 data bytes each)
                           + S7 termination record
                           + CRC16-XMODEM over segment[:-2], stored LITTLE-endian
  GUI  segment           = Blackfin LDR blocks, CRC stored BIG-endian
                           (NXS build has 2 pad bytes before the CRC => cut=4)
"""

def crc_xmodem(d):
    crc = 0
    for b in d:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def srec(rtype, addr, payload):
    """Build one S-record line (without CRLF)."""
    addr_len = {'S0': 2, 'S1': 2, 'S2': 3, 'S3': 4, 'S7': 4, 'S8': 3, 'S9': 2}[rtype]
    body = addr.to_bytes(addr_len, 'big') + payload
    count = len(body) + 1
    chk = (~((count + sum(body)) & 0xFF)) & 0xFF
    return (rtype.encode() + f"{count:02X}".encode()
            + body.hex().upper().encode() + f"{chk:02X}".encode())


def build_srec_segment(ascii_header, s0_payload, chunks, entry_addr,
                       chunk_size=32, rtype='S2'):
    """chunks: list of (addr, bytes) in file order."""
    out = bytearray(ascii_header)
    out += srec('S0', 0, s0_payload) + b'\r\n'
    for addr, blob in chunks:
        for o in range(0, len(blob), chunk_size):
            piece = blob[o:o + chunk_size]
            out += srec(rtype, addr + o, piece) + b'\r\n'
    out += srec('S7', entry_addr, b'') + b'\r\n'
    out += crc_xmodem(bytes(out)).to_bytes(2, 'little')
    return bytes(out)


def build_upd(segments):
    """segments: list of 4 complete segment byte strings (GUI, DRIV, MAIN, PANL)."""
    header = ''.join(f"{len(s)}\r\n" for s in segments).encode()
    return header + b''.join(segments)
