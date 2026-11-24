#!/usr/bin/env python3
"""E04 reference solver.

Inverts gen_e04.py exactly:
  1. read the watermark from the PNG tEXt metadata -> gate coefficients + salt
  2. extract the REAL bits: column-major, R,G,B, bits 2..3, GATED pixels only
  3. XOR-unmask with the geometry+salt keystream
  4. 2-byte big-endian length -> gzip -> UTF-7 decode
  5. (for evidence) show the naive "all pixels, 2 LSB" bait as well
"""
import gzip, hashlib, re, struct, sys
from pathlib import Path
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L


def parse_watermark(text):
    a = int(re.search(r"a=(\d+)", text).group(1))
    b = int(re.search(r"b=(\d+)", text).group(1))
    m = int(re.search(r"mod=(\d+)", text).group(1))
    t = int(re.search(r"target=(\d+)", text).group(1))
    salt = int(re.search(r"salt=0x([0-9A-Fa-f]+)", text).group(1), 16)
    return a, b, m, t, salt


def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, (len(bits) // 8) * 8, 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)


def keystream(n, w, h, salt):
    seed = b"E04" + struct.pack(">HH", w, h) + struct.pack(">I", salt)
    d = hashlib.sha256(seed).digest()
    return (d * (n // len(d) + 1))[:n]


def xor_bytes(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def naive_bait(px, w, h):
    bits = []
    for x in range(w):
        for y in range(h):
            for c in px[x, y]:
                bits.append((c >> 1) & 1)
                bits.append(c & 1)
    raw = bits_to_bytes(bits)
    n = int.from_bytes(raw[:2], "big")
    return raw[2:2 + n].decode("utf-7", "replace")


def real_bytes(px, w, h, a, b, m, t):
    bits = []
    for x in range(w):
        for y in range(h):
            if (a * x + b * y) % m != t:
                continue
            for c in px[x, y]:
                bits.append((c >> 3) & 1)   # MSB of the pair lives in bit 3
                bits.append((c >> 2) & 1)
    return bits_to_bytes(bits)


def solve():
    img = Image.open(L.out_dir("E04") / "camera_roll.png")
    w, h = img.size
    text = dict(getattr(img, "text", {}) or {})
    a, b, m, t, salt = parse_watermark(text["watermark"])
    rgb = img.convert("RGB")
    px = rgb.load()

    raw = real_bytes(px, w, h, a, b, m, t)
    wrapped = xor_bytes(raw, keystream(len(raw), w, h, salt))
    n = int.from_bytes(wrapped[:2], "big")
    flag = gzip.decompress(wrapped[2:2 + n]).decode("utf-7")

    assert flag == L.FLAGS["E04"], flag
    print("[E04] naive bait (decoy):", naive_bait(px, w, h))
    print("[E04] metadata flag (decoy):", text.get("flag"))
    print("[E04] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
