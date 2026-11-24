#!/usr/bin/env python3
"""E03 reference solver (portable, no external tools).

Participant path -- the stash was written then deleted; its data blocks still
sit in the image. Reconciling all stacked layers:

  1. THREE deleted inodes survive (/ledger.dat, /ledger.bak, /notes.tmp). Each
     carves + decompresses to plausible content, but only one is genuine.
  2. The genuine stash is the one whose on-disk byte length equals the `span=`
     field on line 42 of the surviving notes/activity.log.
  3. Its payload is masked with a REPEATING MULTI-BYTE key derived
     arithmetically from TWO raw fields on that same log line: the hostname
     and the integer relay id.  klen = 4 + len(host) % 5 ;
     key[i] = (ord(host[i]) + ((relay >> (8*(i % 4))) & 0xFF) + 7*i) & 0xFF.
  4. After unmasking, one more reversible layer remains:
     zlib-decompress -> byte-reverse -> base64-decode -> plaintext flag.
"""
import base64
import re
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

IMG = L.out_dir("E03") / "safehouse.img"


def log_lines(blob: bytes):
    i = blob.find(b"2026-11-20T")
    if i < 0:
        return None
    region = blob[i:i + 65536].split(b"\x00")[0]
    return region.split(b"\n")


def key_and_span(lines):
    """Pull the two key fields and the selection field off log line 42."""
    if not lines or len(lines) < 42:
        return None, None
    line = lines[41]                                     # 42nd line (1-based)
    mh = re.search(rb"host=(\S+)", line)
    mr = re.search(rb"relay=(\d+)", line)
    ms = re.search(rb"span=(\d+)", line)
    if not (mh and mr and ms):
        return None, None
    host = mh.group(1).decode()
    relay = int(mr.group(1))
    span = int(ms.group(1))
    klen = 4 + (len(host) % 5)
    key = bytes((ord(host[i]) + ((relay >> (8 * (i % 4))) & 0xFF) + 7 * i) & 0xFF
                for i in range(klen))
    return key, span


def find_streams(data: bytes):
    """Return (consumed_length, decompressed_bytes) for every valid zlib stream."""
    out = []
    headers = [b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"]
    for hdr in headers:
        start = 0
        while True:
            i = data.find(hdr, start)
            if i < 0:
                break
            start = i + 1
            d = zlib.decompressobj()
            try:
                payload = d.decompress(data[i:])
            except Exception:
                continue
            if not d.eof:
                continue
            consumed = len(data[i:]) - len(d.unused_data)
            out.append((consumed, payload))
    return out


def solve():
    blob = IMG.read_bytes()
    key, span = key_and_span(log_lines(blob))
    assert key is not None, "activity.log line 42 (relay/span/host) not found"

    unmasked = bytes(b ^ key[i % len(key)] for i, b in enumerate(blob))
    cands = find_streams(unmasked)
    picked = [p for (c, p) in cands if c == span]
    assert len(picked) == 1, \
        f"expected exactly one stash with span={span}, got {len(picked)} (cands={sorted(c for c,_ in cands)})"

    # extra reversible layer: byte-reverse -> base64-decode
    msg = base64.b64decode(picked[0][::-1])
    flag = re.search(rb"FTA\{[a-z0-9_]+\}", msg).group(0).decode()
    assert flag == L.FLAGS["E03"], flag
    print(f"[E03] PASS (key={key.hex()} span={span} streams={len(cands)}) ->", flag)
    return flag


if __name__ == "__main__":
    solve()
