"""Small, dependency-free Motorola S-record parser.

The Pioneer S-record segments have a 32-byte ASCII prefix before the first S0
record.  Non-record lines are therefore ignored, while records themselves can be
strictly checksum-validated.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import List, Optional, Tuple


class SRecError(ValueError):
    """Raised when a strict S-record parse encounters malformed input."""


_ADDRESS_BYTES = {
    "0": 2,
    "1": 2,
    "2": 3,
    "3": 4,
    "7": 4,
    "8": 3,
    "9": 2,
}


def parse_srec(
    text_bytes: bytes, validate: bool = False
) -> Tuple[Optional[bytes], List[Tuple[int, bytes]], List[Tuple[str, int]]]:
    """Parse Motorola S-record text.

    Returns ``(header, chunks, entries)``. ``header`` is the S0 data payload,
    ``chunks`` contains ``(address, bytes)`` pairs for S1/S2/S3 records, and
    ``entries`` contains termination-record type/address pairs.

    When ``validate`` is true, malformed hex, lengths, unsupported record types,
    and checksum failures raise :class:`SRecError`.
    """

    chunks: List[Tuple[int, bytes]] = []
    entries: List[Tuple[str, int]] = []
    header: Optional[bytes] = None

    for line_number, raw_line in enumerate(
        text_bytes.replace(b"\r\n", b"\n").split(b"\n"), start=1
    ):
        line = raw_line.strip()
        if line and not line.startswith(b"S"):
            # Pioneer places its 32-byte ASCII segment header directly before S0,
            # without a line break. Find the first plausible embedded record.
            for candidate in range(max(0, len(line) - 3)):
                if (
                    line[candidate : candidate + 1] == b"S"
                    and line[candidate + 1 : candidate + 2] in b"0123789"
                    and all(chr(value) in "0123456789abcdefABCDEF" for value in line[candidate + 2 : candidate + 4])
                ):
                    line = line[candidate:]
                    break
        if not line or not line.startswith(b"S"):
            continue
        try:
            record_type = chr(line[1])
            address_bytes = _ADDRESS_BYTES[record_type]
            count = int(line[2:4], 16)
            encoded = line[4:]
            if len(encoded) != count * 2:
                raise SRecError(
                    f"line {line_number}: count says {count} bytes, "
                    f"found {len(encoded) // 2}"
                )
            record = bytes.fromhex(encoded.decode("ascii"))
            if len(record) < address_bytes + 1:
                raise SRecError(f"line {line_number}: record is too short")
            if (count + sum(record)) & 0xFF != 0xFF:
                raise SRecError(f"line {line_number}: checksum mismatch")
        except (IndexError, KeyError, UnicodeDecodeError, ValueError) as exc:
            if validate:
                if isinstance(exc, SRecError):
                    raise
                raise SRecError(f"line {line_number}: malformed S-record") from exc
            continue

        address = int.from_bytes(record[:address_bytes], "big")
        payload = record[address_bytes:-1]
        if record_type == "0":
            header = payload
        elif record_type in ("1", "2", "3"):
            chunks.append((address, payload))
        elif record_type in ("7", "8", "9"):
            entries.append((record_type, address))

    if validate and not chunks:
        raise SRecError("no S1/S2/S3 data records found")
    return header, chunks, entries


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Inspect a Motorola S-record segment")
    parser.add_argument("path", type=Path)
    args = parser.parse_args(argv)

    header, chunks, entries = parse_srec(args.path.read_bytes(), validate=True)
    total = sum(len(data) for _, data in chunks)
    low = min(address for address, _ in chunks)
    high = max(address + len(data) for address, data in chunks)
    print(f"header: {header!r}")
    print(f"records: {len(chunks)}")
    print(f"data bytes: {total} (0x{total:X})")
    print(f"address range: 0x{low:X}-0x{high:X}")
    print("entries:", ", ".join(f"S{kind}=0x{address:X}" for kind, address in entries))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
