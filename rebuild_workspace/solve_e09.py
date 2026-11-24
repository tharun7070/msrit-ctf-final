#!/usr/bin/env python3
"""E09 reference solver (private).

Inverts chopshop.js WITHOUT a browser, by mirroring its algorithm exactly:

  1. parse the rotated string array out of `var _0x4b1d = [ ... ];`;
  2. parse the rotation amount ROT from the rotation IIFE `})(_0x4b1d, ROT);`
     and un-rotate: raw[i] = rotated[(i - ROT) mod n];
  3. recover STORED (hex) and TARGET (hex) from the rotated array;
  4. recover the seed S0 = STORED ^ SEED_XOR (the arithmetic layer);
  5. regenerate the xorshift32 keystream, XOR TARGET bytes, base64-decode.

Reads ONLY artifacts in L.out_dir('E09').
"""
import base64
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

# constants of the algorithm (mirror of gen_e09.py)
SEED_XOR = 0xA5A5F00D
IDX_SEED = 1
IDX_TARGET = 4
ARRAY_VAR = "_0x4b1d"


def xorshift32_keystream(seed: int, n: int) -> bytes:
    x = seed & 0xFFFFFFFF
    out = bytearray()
    for _ in range(n):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17)
        x ^= (x << 5) & 0xFFFFFFFF
        x &= 0xFFFFFFFF
        out.append(x & 0xFF)
    return bytes(out)


def parse_chopshop(js: str):
    """Return (rotated_array, rot)."""
    m = re.search(r"var\s+" + re.escape(ARRAY_VAR) + r"\s*=\s*\[(.*?)\];", js, re.S)
    assert m, "string array not found"
    raw = re.findall(r'"([^"]*)"', m.group(1))
    assert raw, "string array empty"

    m = re.search(r"\}\)\s*\(\s*" + re.escape(ARRAY_VAR) + r"\s*,\s*(\d+)\s*\)", js)
    assert m, "rotation amount not found"
    rot = int(m.group(1))

    # the IIFE rotates left by `rot`: rotated[i] = raw[(i + rot) % n]
    n = len(raw)
    rotated = [raw[(i + rot) % n] for i in range(n)]
    return rotated, rot


def solve():
    js = (L.out_dir("E09") / "chopshop.js").read_text(encoding="utf-8")
    rotated, rot = parse_chopshop(js)

    target_hex = rotated[IDX_TARGET]
    stored = int(rotated[IDX_SEED], 16)
    seed = (stored ^ SEED_XOR) & 0xFFFFFFFF

    t = bytes.fromhex(target_hex)
    k = xorshift32_keystream(seed, len(t))
    b = bytes(x ^ y for x, y in zip(t, k))
    flag = base64.b64decode(b).decode("ascii")

    assert flag == L.FLAGS["E09"], (flag, L.FLAGS["E09"])
    print("[E09] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
