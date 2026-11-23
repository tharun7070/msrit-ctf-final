#!/usr/bin/env python3
"""E03 reference solver (portable, no external tools).

Participant path:
  1. The stash was written then deleted; its data blocks still sit in the image.
  2. It is zlib-compressed then masked with a single byte. That byte = XOR of the
     ASCII codes of the 3rd and 7th characters of the hostname field on the 42nd
     line of notes/activity.log.
  3. Scan the raw image for the masked zlib stream and decompress.
"""
import re, sys, zlib
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

IMG = L.out_dir("E03") / "safehouse.img"
HOST = re.compile(rb"host=(\S+) ")


def key_from_log(blob: bytes):
    i = blob.find(b"2026-11-20T")
    if i < 0:
        return None
    region = blob[i:i + 16384].split(b"\x00")[0]
    hosts = [m.group(1).decode() for m in HOST.finditer(region)]
    if len(hosts) < 42:
        return None
    h = hosts[41]                      # 42nd line (1-based)
    return ord(h[2]) ^ ord(h[6])


def carve(blob: bytes, key: int, limit=None):
    headers = [b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"]
    data = blob if limit is None else blob[:limit]
    unmasked = bytes(b ^ key for b in data)
    for hdr in headers:
        start = 0
        while True:
            i = unmasked.find(hdr, start)
            if i < 0:
                break
            for end in range(i + 8, min(len(unmasked), i + 4096)):
                try:
                    out = zlib.decompress(unmasked[i:end])
                except Exception:
                    continue
                if b"FTA{" in out:
                    return out
            start = i + 1
    return None


def solve():
    blob = IMG.read_bytes()
    key = key_from_log(blob)
    data = carve(blob, key) if key is not None else None
    if data is None:
        for k in range(256):
            data = carve(blob, k, limit=131072)
            if data:
                key = k
                break
    assert data, "stash not recovered"
    flag = re.search(r"FTA\{[a-z0-9_]+\}", data.decode("utf-8", "replace")).group(0)
    assert flag == L.FLAGS["E03"], flag
    print(f"[E03] PASS (recovery byte={key}) ->", flag)
    return flag


if __name__ == "__main__":
    solve()
