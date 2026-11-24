#!/usr/bin/env python3
"""E04 -- Del Perro Camera Roll (hardened multi-layer PNG steganography).

Organizer tooling. Participants only receive camera_roll.png + README.txt; every
layer below has to be peeled in order. None of this is spelled out for them.

Layers:
  * Carrier   : deterministic synthetic RGB still (fixed seed).
  * DECOY     : 2 LSBs (bits 0..1) of EVERY pixel, column-major R,G,B,
                MSB-first, hold a 2-byte big-endian length + a fake
                "burner bait" message.  A tool that scans all pixels this way
                finds bait, not the drop.
  * GATE      : only the pixels where (3x + 5y) % 7 == 4 are ever touched by
                the real payload.  The coefficients live in the image
                watermark (tEXt key "watermark") -- inferable, never spelled
                out in README.txt.
  * REAL plane: bits 2..3 of the R, then G, then B channel of gated pixels,
                column-major, MSB-first.
  * MASK      : the recovered byte stream is XORed with a repeating key =
                SHA256(b"E04" + be16(W) + be16(H) + be32(SALT)); SALT is
                logged in the watermark.
  * WRAP      : after unmasking, 2-byte big-endian length + gzip(utf-7(flag)).
  * DECOY meta: tEXt "flag" carries a plausible but WRONG FTA{...}.
Private organizer tooling.
"""
import gzip, hashlib, math, random, struct, sys
from pathlib import Path
from PIL import Image
from PIL.PngImagePlugin import PngInfo

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

W, H = 160, 120

# --- hidden parameters (watermark holds these; README holds none of them) ---
GATE_A, GATE_B, GATE_M, GATE_T = 3, 5, 7, 4     # (a*x + b*y) % m == t
SALT = 0xE04C0DE                                # logged (as hex) in the watermark

# --- decoys ----------------------------------------------------------------
DECOY_FLAG = "FTA{lsb_n0t_th1s_w4y_r00k13}"     # wrong flag, in metadata
DECOY_MSG = ("burner bait :: drop aborted, fleet rotated. "
             "decoy token FTA{d3c0y_2_lsb_b41t_4nd_sw1tch}")


def build_carrier():
    """Synthetic Del Perro night skyline -- deterministic, looks like a snapshot."""
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


def gated(x, y, a=GATE_A, b=GATE_B, m=GATE_M, t=GATE_T):
    return (a * x + b * y) % m == t


def bytes_to_bits(bs):
    bits = []
    for byte in bs:
        for sh in range(7, -1, -1):
            bits.append((byte >> sh) & 1)
    return bits


def keystream(n, w=W, h=H, salt=SALT):
    """Repeating XOR key derived from the frame geometry + the watermark salt."""
    seed = b"E04" + struct.pack(">HH", w, h) + struct.pack(">I", salt)
    d = hashlib.sha256(seed).digest()
    return (d * (n // len(d) + 1))[:n]


def xor_bytes(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def embed_decoy(px):
    """Plant the naive-readable bait in the low 2 bits of every pixel."""
    stream = len(DECOY_MSG.encode("utf-7")).to_bytes(2, "big") + DECOY_MSG.encode("utf-7")
    bits = bytes_to_bits(stream)
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


def embed_real(px, masked: bytes):
    """Plant the real (masked) stream in bits 2..3 of GATED pixels only."""
    bits = bytes_to_bits(masked)
    k = 0
    for x in range(W):
        for y in range(H):
            if not gated(x, y):
                continue
            r, g, b = px[x, y]
            out = []
            for c in (r, g, b):
                if k + 2 <= len(bits):
                    two = (bits[k] << 1) | bits[k + 1]
                    c = (c & 0xF3) | (two << 2)      # clear bits 2..3, write
                    k += 2
                out.append(c)
            px[x, y] = tuple(out)
    if k < len(bits):
        raise ValueError("carrier too small for payload")
    return k


README = """DEL PERRO CCTV EXPORT
----------------------
Still #4471 recovered from a burnt dashcam of the Vinewood security
contractor. The frame is heavier than its picture deserves, and the operator
who parked it here left more than one thing inside.

He never wrote a file -- he stained the still. The frame carries a watermark,
and only the pixels that watermark blesses were ever used. Scan every pixel's
low bits instead and you will pull the burner bait he left for that exact
mistake: a tidy little message that is not the drop.

The operator still cuts his drops the way Del Perro's old trading cards were
trimmed -- down a column, top to bottom. Whatever the blessed pixels hold has
been smeared with a mask built from the frame's own geometry and from a salt
the watermark logs, then folded through two further wraps before it will read
as text at all.

Recover the drop. The first bytes of the unwrapped stream are its own
big-endian length.
"""


def main():
    out = L.out_dir("E04")
    img = build_carrier()
    px = img.load()

    # real payload: UTF-7 -> gzip -> length prefix -> XOR mask
    payload = L.FLAGS["E04"].encode("utf-7")
    gz = gzip.compress(payload, compresslevel=9, mtime=0)
    wrapped = len(gz).to_bytes(2, "big") + gz
    ks = keystream(len(wrapped))
    masked = xor_bytes(wrapped, ks)

    embed_decoy(px)
    used = embed_real(px, masked)

    info = PngInfo()
    info.add_text("Comment", "DEL PERRO CCTV EXPORT // still 4471 // do not distribute")
    info.add_text("watermark",
                  f"DUSKGRID a={GATE_A},b={GATE_B},mod={GATE_M},target={GATE_T} "
                  f"salt=0x{SALT:08X}")
    info.add_text("flag", DECOY_FLAG)
    img.save(out / "camera_roll.png", pnginfo=info)
    (out / "README.txt").write_text(README, encoding="utf-8")
    print(f"[E04] wrapped {len(gz)}B -> {used} gated payload bits -> "
          f"{(out / 'camera_roll.png').name}")


if __name__ == "__main__":
    main()
