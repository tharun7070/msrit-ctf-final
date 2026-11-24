#!/usr/bin/env python3
"""Nightshift loader -- triage stub (incomplete).

Walks the container's section table and dumps the retained debug build record
as described in LOADER_NOTES.txt.  It does not read the live PACK body.

Run:  python unpack_stub.py
"""
import base64
import struct
import sys
from pathlib import Path

MAGIC = b"NSLF"


def sections(buf):
    i = len(MAGIC) + 3            # magic(4) + version(2) + spare(1)
    out = []
    while i + 8 <= len(buf):
        tag = buf[i:i + 4]
        ln = struct.unpack("<I", buf[i + 4:i + 8])[0]
        i += 8
        out.append((tag, buf[i:i + ln]))
        i += ln
    return out


def main():
    here = Path(__file__).resolve().parent
    buf = (here / "nightshift_loader.bin").read_bytes()
    if not buf.startswith(MAGIC):
        print("not a Nightshift loader container")
        return
    sec = dict(sections(buf))
    for tag, data in sections(buf):
        print("section %-4s %5d bytes" % (tag.decode("latin1"), len(data)))
    # the field note says the cached build flag is XOR-masked with 0x5A and
    # base64-encoded -- that route decodes cleanly, so we trust it for now.
    dbg = base64.b64decode(sec[b"DBUG"])
    print("cached build flag:", bytes(b ^ 0x5A for b in dbg).decode("ascii", "replace"))


if __name__ == "__main__":
    sys.exit(main())
