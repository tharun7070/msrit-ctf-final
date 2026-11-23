#!/usr/bin/env python3
"""E04 — Del Perro Camera Roll (custom PNG steganography + UTF-7).

Scheme (documented to participants):
  * Carrier is an RGB PNG ("camera roll" still).
  * Payload bits are packed 2 bits (LSBs) per channel, in COLUMN-MAJOR order:
      for x in range(W): for y in range(H): channels R,G,B.
  * Bit order inside each byte is MSB-first.
  * First 2 decoded bytes = big-endian payload length L; next L bytes are the
    message encoded as UTF-7.
Private organizer tooling.
"""
import math, random, sys
from pathlib import Path
from PIL import Image

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

W, H = 160, 120


def build_carrier():
    """Synthetic Del Perro night skyline — deterministic, looks like a snapshot."""
    rnd = random.Random(0xDE1FE440)
    img = Image.new("RGB", (W, H))
    px = img.load()
    for y in range(H):
        for x in range(W):
            # vertical dusk gradient
            r = int(20 + 60 * (y / H))
            g = int(10 + 30 * (y / H))
            b = int(60 + 90 * (y / H))
            # city skyline blocks
            col = (x * 7) // 11
            top = H // 3 + int(18 * math.sin(col * 0.7)) - (col % 5) * 3
            if y > top:
                lit = 200 if ((x * 13 + y * 5) % 71) < 18 else 40
                r, g, b = lit, lit - 20, lit - 60
            r = max(0, min(255, r + rnd.randint(-6, 6)))
            g = max(0, min(255, g + rnd.randint(-6, 6)))
            b = max(0, min(255, b + rnd.randint(-6, 6)))
            px[x, y] = (r & 0xFC | rnd.randint(0, 3),
                        g & 0xFC | rnd.randint(0, 3),
                        b & 0xFC | rnd.randint(0, 3))
    return img


def embed(img, message: str):
    payload = message.encode("utf-7")
    stream = len(payload).to_bytes(2, "big") + payload
    bits = []
    for byte in stream:
        for sh in range(7, -1, -1):
            bits.append((byte >> sh) & 1)
    if len(bits) > W * H * 3 * 2:
        raise ValueError("carrier too small for payload")
    px = img.load()
    k = 0
    for x in range(W):
        for y in range(H):
            r, g, b = px[x, y]
            out = []
            for c in (r, g, b):
                if k + 2 <= len(bits):
                    two = (bits[k] << 1) | bits[k + 1]
                    c = (c & 0xFC) | two
                    k += 2
                out.append(c)
            px[x, y] = tuple(out)
    return k


def main():
    out = L.out_dir("E04")
    img = build_carrier()
    used = embed(img, L.FLAGS["E04"])
    img.save(out / "camera_roll.png")
    (out / "README.txt").write_text(
        "DEL PERRO CCTV EXPORT\n"
        "----------------------\n"
        "Still #4471 recovered from a burnt dashcam of the Vinewood security\n"
        "contractor.\n\n"
        "The operator's dead-drop tooling packs recon notes into images:\n"
        "  - 2 least-significant bits per colour channel, R then G then B.\n"
        "  - Pixels are read COLUMN by column (down a column, then next column).\n"
        "  - Bits fill each byte most-significant first.\n"
        "  - The first 2 decoded bytes are a big-endian length, then that many\n"
        "    bytes of the message (the message alphabet is UTF-7).\n",
        encoding="utf-8")
    print(f"[E04] embedded {used} payload bits -> {(out / 'camera_roll.png').name}")


if __name__ == "__main__":
    main()
