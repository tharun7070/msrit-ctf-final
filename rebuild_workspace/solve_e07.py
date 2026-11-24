#!/usr/bin/env python3
"""E07 reference solver -- Wanted Poster.

Inverts gen_e07.py exactly:
  1. read the printed CIPHERTEXT line (V) from the PNG tEXt record
     ("ciphertext") -- the same line the poster renders;
  2. sample the seal swatch row near the bottom: hue bin -> letter, recovering
     the Vigenere keyword. (DEPUTIZE.txt explains the map but advertises a DECOY
     watchword; the seal is authoritative and the decoy is ignored.)
  3. Vigenere-decrypt V (letters only) -> rail-fence text R;
  4. rail-fence decode R (rail count read from DEPUTIZE.txt) -> flag.
"""
import colorsys
import re
import sys
from pathlib import Path

from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L


def vigenere_decrypt(text, key):
    """Case-preserving Vigenere over letters only; non-letters pass through and
    do NOT advance the key (inverse of gen.vigenere_encrypt)."""
    k = [ord(c.lower()) - 97 for c in key if c.isalpha()]
    assert k, "empty key"
    out, ki = [], 0
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 - k[ki % len(k)]) % 26 + 97))
            ki += 1
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 - k[ki % len(k)]) % 26 + 65))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def rail_fence_decode(text, rails):
    """Inverse of the zig-zag rail_fence_encode."""
    if rails <= 1 or rails >= len(text):
        return text
    n = len(text)
    pattern, rail, direction = [], 0, 1
    for _ in range(n):
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    counts = [0] * rails
    for r in pattern:
        counts[r] += 1
    rails_txt, idx = [], 0
    for r in range(rails):
        rails_txt.append(text[idx:idx + counts[r]])
        idx += counts[r]
    pos = [0] * rails
    out = []
    for r in pattern:
        out.append(rails_txt[r][pos[r]])
        pos[r] += 1
    return "".join(out)


def read_ciphertext(path):
    """The CIPHERTEXT line recorded in the poster's PNG tEXt metadata."""
    img = Image.open(path)
    text = dict(getattr(img, "text", {}) or {})
    assert "ciphertext" in text, "ciphertext record missing from poster"
    return text["ciphertext"]


def read_seal_key(path):
    """Sample the seal swatch row: hue -> bin -> letter."""
    img = Image.open(path).convert("RGB")
    W, H = img.size
    px = img.load()

    def colorful(c):
        return max(c) >= 120 and (max(c) - min(c)) >= 80

    best_row, best = None, -1
    for y in range(int(H * 0.70), int(H * 0.98)):
        cnt = sum(1 for x in range(W) if colorful(px[x, y]))
        if cnt > best:
            best, best_row = cnt, y
    assert best_row is not None and best > 0, "seal row not found"

    letters, x = [], 0
    while x < W:
        if colorful(px[x, best_row]):
            x0 = x
            while x < W and colorful(px[x, best_row]):
                x += 1
            if x - x0 >= 12:
                cx = (x0 + x - 1) // 2
                r, g, b = px[cx, best_row]
                h, _, _ = colorsys.rgb_to_hsv(r / 255, g / 255, b / 255)
                letters.append(chr(ord("a") + int(h * 26) % 26))
        else:
            x += 1
    assert letters, "no seal swatches detected"
    return "".join(letters)


def read_lsb_payload(path, max_bytes=64):
    """TRAP #1: the naive little-endian-bits LSB payload (blue channel)."""
    img = Image.open(path).convert("RGB")
    W, H = img.size
    px = img.load()
    bits, done = [], False
    for y in range(H):
        for x in range(W):
            bits.append(px[x, y][2] & 1)
            if len(bits) >= max_bytes * 8:
                done = True
                break
        if done:
            break
    out = bytearray()
    for i in range(0, len(bits) - 7, 8):
        v = 0
        for j in range(8):
            v |= bits[i + j] << j
        out.append(v)
    return bytes(out)


def parse_rails(note):
    m = re.search(r"RAIL\s*COUNT\s*[:=]\s*(\d+)", note, re.I)
    assert m, "rail count not found in DEPUTIZE.txt"
    return int(m.group(1))


def solve():
    out = L.out_dir("E07")
    poster = out / "wanted_poster.png"
    note = (out / "DEPUTIZE.txt").read_text(encoding="utf-8")

    V = read_ciphertext(poster)
    key = read_seal_key(poster)
    rails = parse_rails(note)

    flag = rail_fence_decode(vigenere_decrypt(V, key), rails)
    assert flag == L.FLAGS["E07"], (flag, L.FLAGS["E07"])
    print("[E07] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
