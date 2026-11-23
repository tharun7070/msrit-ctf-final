#!/usr/bin/env python3
"""E04 reference solver: column-major 2-LSB extraction + UTF-7 decode."""
import sys
from pathlib import Path
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L


def solve():
    img = Image.open(L.out_dir("E04") / "camera_roll.png").convert("RGB")
    w, h = img.size
    px = img.load()
    bits = []
    for x in range(w):
        for y in range(h):
            for c in px[x, y]:
                bits.append((c >> 1) & 1)
                bits.append(c & 1)
    out = bytearray()
    for i in range(0, (len(bits) // 8) * 8, 8):
        out.append(int("".join(str(b) for b in bits[i:i + 8]), 2))
    n = int.from_bytes(out[:2], "big")
    flag = bytes(out[2:2 + n]).decode("utf-7")
    assert flag == L.FLAGS["E04"], flag
    print("[E04] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
