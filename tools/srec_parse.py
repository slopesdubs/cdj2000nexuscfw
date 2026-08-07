import sys

def parse_srec(text_bytes):
    """Parse Motorola S-record text, return dict: {'data': {addr: bytes}, 'entries': [(type, addr)]}"""
    lines = text_bytes.replace(b'\r\n', b'\n').split(b'\n')
    chunks = []  # (addr, bytes)
    entries = []
    header = None
    for ln in lines:
        ln = ln.strip()
        if not ln or not ln.startswith(b'S'):
            continue
        rtype = chr(ln[1])
        try:
            count = int(ln[2:4], 16)
        except Exception:
            continue
        payload = ln[4:4+count*2]
        if rtype == '0':
            header = bytes.fromhex(payload.decode())
        elif rtype in ('1','2','3'):
            addr_len = {'1':4,'2':6,'3':8}[rtype]
            addr = int(payload[:addr_len], 16)
            data = bytes.fromhex(payload[addr_len:-2].decode())
            chunks.append((addr, data))
        elif rtype in ('7','8','9'):
            addr_len = {'7':8,'8':6,'9':4}[rtype]
            addr = int(payload[:addr_len], 16)
            entries.append((rtype, addr))
    return header, chunks, entries

for name in ['DRIV','MAIN','PANL']:
    pass

data = open('C2KNXS.UPD','rb').read()
sizes = {'GUI':2015268,'DRIV':388690,'MAIN':7062204,'PANL':98888}
off = 33
segs = {}
for n in ['GUI','DRIV','MAIN','PANL']:
    segs[n] = data[off:off+sizes[n]]
    off += sizes[n]

for n in ['DRIV','MAIN','PANL']:
    header, chunks, entries = parse_srec(segs[n])
    total_bytes = sum(len(d) for a,d in chunks)
    minaddr = min(a for a,d in chunks)
    maxaddr = max(a+len(d) for a,d in chunks)
    print(f"=== {n} ===")
    print("header:", header)
    print("num chunks:", len(chunks), "total data bytes:", hex(total_bytes))
    print("addr range:", hex(minaddr), '-', hex(maxaddr))
    print("entry records:", [(t, hex(a)) for t,a in entries])
    print()
