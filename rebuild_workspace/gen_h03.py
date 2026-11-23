#!/usr/bin/env python3
"""H03 — Impound Evidence Matryoshka (5-layer matryoshka).

Self-contained generator. Produces, in L.out_dir("H03"):
  * impound_camera.png  — participant-facing carrier (LSB stego + EXIF GPS)
  * EVIDENCE_NOTE.txt   — field note: LSB scheme, GPS formula, PBKDF2/AES
                          params, MTX-1 matrix-code decoder, fleet ledger.

Pipeline (nested like a matryoshka doll):
  Layer 1  PNG LSB stego (column-major, 2 bits/channel) hides an encrypted blob
           + EXIF GPS tags (hand-built TIFF) live in the eXIf chunk.
  Layer 2  blob = nonce(16) || AES-256-CTR(PBKDF2-HMAC-SHA256(passphrase, salt)).
           passphrase is derived from the EXIF GPS coordinates.
  Layer 3  plaintext is a small PNG holding a custom "MTX-1" black/white matrix
           code; decoding the matrix yields the token.
  Layer 4  the token LOOKS like url-safe base64 but is really a Huffman
           bitstream (code table provided as a "fleet ledger").
  Layer 5  the Huffman output is Python source that prints the fixed flag.

CORRECTION (see SOLUTION.md): the original spec asked for a TIMESTAMP-DEPENDENT
flag; that is non-reproducible and unfair, so the final stage prints a FIXED
deterministic flag. No QR library is available, so the QR layer is replaced by
a self-implemented MTX-1 matrix code.

Private organizer tooling — never ship this file to participants.
"""
import base64, heapq, io, struct, sys
from collections import Counter
from pathlib import Path

import numpy as np
from PIL import Image, PngImagePlugin
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

# ---------------------------------------------------------------------------
# Fixed parameters (also documented in EVIDENCE_NOTE.txt)
# ---------------------------------------------------------------------------
FLAG = L.FLAGS["H03"]

# EXIF GPS: (deg, min, sec_num, sec_den, ref)
GPS_LAT = (34, 3, 792, 100, "N")     # 34 deg 03' 07.92" N
GPS_LON = (118, 14, 3732, 100, "W")  # 118 deg 14' 37.32" W
PBKDF2_SALT = b"lspd-impound-2026"    # 16 bytes
PBKDF2_ITER = 100000
MATRIX_N = 41        # MTX-1 grid is N x N modules
MODULE_PX = 6        # pixels per module
QUIET = 4            # quiet-zone width in modules
CARRIER_W, CARRIER_H = 200, 160

DECOYS = {
    "text": "FTA{l5b_t3xt_chunk_d3c0y}",
    "exif": "FTA{3x1f_gps_tr4p_d3c0y}",
    "trail": "FTA{tr41l1ng_z0n3_d3c0y}",
}


# ---------------------------------------------------------------------------
# Hand-built EXIF (TIFF) with a GPS IFD — no piexif.
# ---------------------------------------------------------------------------
BYTE, ASCII, SHORT, LONG, RATIONAL, UNDEFINED = 1, 2, 3, 4, 5, 7
TSIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1}


def _rat(num, den):
    return struct.pack("<II", num, den)


def _ifd_bytes(entries, base_offset):
    """entries: [(tag, typ, count, value_bytes)] sorted by tag.
    Returns (ifd_bytes, data_bytes); values >4 bytes are relocated into
    data_bytes and referenced by base_offset + position."""
    out = bytearray(struct.pack("<H", len(entries)))
    data = bytearray()
    for tag, typ, count, val in entries:
        raw = len(val)
        out += struct.pack("<HHI", tag, typ, count)
        if raw <= 4:
            out += val + b"\x00" * (4 - raw)
        else:
            out += struct.pack("<I", base_offset + len(data))
            data += val
    out += struct.pack("<I", 0)
    return bytes(out), bytes(data)


def build_exif(description: str) -> bytes:
    """Minimal EXIF blob: 'Exif\\0\\0' + little-endian TIFF with IFD0
    (ImageDescription, Model, GPSInfo) + GPS IFD (lat/lon)."""
    desc = description.encode("ascii") + b"\x00"
    model = b"LS-IMPOUND-CAM3\x00"
    ifd0_base = [
        (0x010E, ASCII, len(desc), desc),          # ImageDescription (decoy)
        (0x0110, ASCII, len(model), model),        # Model
    ]
    n0 = len(ifd0_base) + 1                        # + GPS pointer
    n_gps = 4
    off_ifd0 = 8
    off_gps = off_ifd0 + (2 + 12 * n0 + 4)
    off_data0 = off_gps + (2 + 12 * n_gps + 4)

    ifd0 = ifd0_base + [(0x8825, LONG, 1, struct.pack("<I", off_gps))]
    ifd0.sort(key=lambda e: e[0])
    ifd0_bytes, data0 = _ifd_bytes(ifd0, off_data0)
    off_datagps = off_data0 + len(data0)

    gps = [
        (0x0001, ASCII, 2, GPS_LAT[4].encode() + b"\x00"),
        (0x0002, RATIONAL, 3,
         _rat(GPS_LAT[0], 1) + _rat(GPS_LAT[1], 1) + _rat(GPS_LAT[2], GPS_LAT[3])),
        (0x0003, ASCII, 2, GPS_LON[4].encode() + b"\x00"),
        (0x0004, RATIONAL, 3,
         _rat(GPS_LON[0], 1) + _rat(GPS_LON[1], 1) + _rat(GPS_LON[2], GPS_LON[3])),
    ]
    gps.sort(key=lambda e: e[0])
    gps_bytes, datagps = _ifd_bytes(gps, off_datagps)

    tiff = (struct.pack("<2sHI", b"II", 42, off_ifd0)
            + ifd0_bytes + gps_bytes + data0 + datagps)
    return b"Exif\x00\x00" + tiff


# ---------------------------------------------------------------------------
# GPS -> passphrase (documented numeric formula)
# ---------------------------------------------------------------------------
def _decimal(dms):
    deg, mn, sn, sd, _ref = dms
    return deg + mn / 60 + (sn / sd) / 3600


def gps_code() -> str:
    """10-digit code: last five digits of each scaled coordinate magnitude."""
    a = round(abs(_decimal(GPS_LAT)) * 10000) % 100000
    b = round(abs(_decimal(GPS_LON)) * 10000) % 100000
    return f"{a:05d}{b:05d}"


def passphrase() -> str:
    return "IMPOUND-" + gps_code()


# ---------------------------------------------------------------------------
# Layer 5 -> 4: Huffman coding of the source program
# ---------------------------------------------------------------------------
def huffman_codes(text):
    freq = Counter(text)
    heap = [[f, i, ch] for i, (ch, f) in enumerate(sorted(freq.items()))]
    heapq.heapify(heap)
    uid = len(heap)
    while len(heap) > 1:
        f1, _, t1 = heapq.heappop(heap)
        f2, _, t2 = heapq.heappop(heap)
        heapq.heappush(heap, [f1 + f2, uid, (t1, t2)])
        uid += 1
    root = heap[0][2]
    codes = {}

    def walk(node, prefix):
        if isinstance(node, str):
            codes[node] = prefix or "0"
            return
        walk(node[0], prefix + "0")
        walk(node[1], prefix + "1")

    walk(root, "")
    return codes


def bits_to_bytes(bits):
    bits = bits + [0] * ((8 - len(bits) % 8) % 8)
    return bytes(int("".join(str(b) for b in bits[i:i + 8]), 2)
                 for i in range(0, len(bits), 8))


def bytes_to_bits(data):
    out = []
    for byte in data:
        for sh in range(7, -1, -1):
            out.append((byte >> sh) & 1)
    return out


def build_source() -> str:
    parts = [FLAG[:14], FLAG[14:26], FLAG[26:]]
    joined = ", ".join(repr(p) for p in parts)
    return f'print("".join([{joined}]))\n'


# ---------------------------------------------------------------------------
# Layer 3: MTX-1 matrix code (render + documented decoder)
# ---------------------------------------------------------------------------
def render_matrix(token: str) -> Image.Image:
    payload = len(token).to_bytes(2, "big") + token.encode("ascii")
    bits = bytes_to_bits(payload)
    n = MATRIX_N
    grid = np.zeros((n, n), dtype=np.uint8)
    for i in range(n):                       # sync ladder on row 0 / col 0
        grid[0, i] = 1 if i % 2 == 0 else 0
        grid[i, 0] = 1 if i % 2 == 0 else 0
    k = 0
    for y in range(1, n):                    # data modules, row-major
        for x in range(1, n):
            if k < len(bits):
                grid[y, x] = bits[k]
                k += 1
    assert k == len(bits), "matrix too small for payload"
    size = (n + 2 * QUIET) * MODULE_PX
    arr = np.full((size, size), 255, dtype=np.uint8)
    for y in range(n):
        for x in range(n):
            if grid[y, x]:
                y0 = (y + QUIET) * MODULE_PX
                x0 = (x + QUIET) * MODULE_PX
                arr[y0:y0 + MODULE_PX, x0:x0 + MODULE_PX] = 0
    return Image.fromarray(arr, "L")


def matrix_png_bytes(token: str) -> bytes:
    buf = io.BytesIO()
    render_matrix(token).save(buf, "PNG")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Layer 1: carrier image
# ---------------------------------------------------------------------------
def build_carrier() -> Image.Image:
    """Synthetic impound-lot surveillance still (deterministic noise)."""
    import random
    rnd = random.Random(0x1A703671)
    img = Image.new("RGB", (CARRIER_W, CARRIER_H))
    px = img.load()
    for y in range(CARRIER_H):
        for x in range(CARRIER_W):
            # sodium-vapor night wash
            r = int(30 + 90 * (y / CARRIER_H))
            g = int(20 + 55 * (y / CARRIER_H))
            b = int(15 + 30 * (y / CARRIER_H))
            # chain-link fence + floodlight cones
            if (x + y) % 9 == 0:
                r, g, b = r + 60, g + 60, b + 55
            if ((x - 60) ** 2 + (y - 40) ** 2) < 900:
                r, g, b = min(255, r + 120), min(255, g + 110), min(255, b + 90)
            # parked vehicle silhouettes
            for cx, cw, cy in ((30, 34, 120), (95, 40, 118), (160, 30, 122)):
                if cx <= x < cx + cw and cy <= y < cy + 26:
                    r, g, b = 25, 24, 28
            r = max(0, min(255, r + rnd.randint(-5, 5)))
            g = max(0, min(255, g + rnd.randint(-5, 5)))
            b = max(0, min(255, b + rnd.randint(-5, 5)))
            px[x, y] = (r & 0xFC | rnd.randint(0, 3),
                        g & 0xFC | rnd.randint(0, 3),
                        b & 0xFC | rnd.randint(0, 3))
    return img


def embed_lsb(img, blob: bytes) -> int:
    stream = len(blob).to_bytes(4, "big") + blob
    bits = bytes_to_bits(stream)
    cap = CARRIER_W * CARRIER_H * 3 * 2
    assert len(bits) <= cap, f"carrier too small: {len(bits)} > {cap}"
    px = img.load()
    k = 0
    for x in range(CARRIER_W):          # COLUMN-MAJOR
        for y in range(CARRIER_H):
            r, g, b = px[x, y]
            out = []
            for c in (r, g, b):
                if k + 2 <= len(bits):
                    c = (c & 0xFC) | ((bits[k] << 1) | bits[k + 1])
                    k += 2
                out.append(c)
            px[x, y] = tuple(out)
    return k


# ---------------------------------------------------------------------------
# Build the nested chain
# ---------------------------------------------------------------------------
def encrypt_blob(plaintext: bytes) -> bytes:
    pwd = passphrase().encode()
    key = PBKDF2(pwd, PBKDF2_SALT, dkLen=32, count=PBKDF2_ITER, hmac_hash_module=SHA256)
    nonce = bytes(range(16))                     # fixed initial counter block
    ct = AES.new(key, AES.MODE_CTR, nonce=b"",
                 initial_value=int.from_bytes(nonce, "big")).encrypt(plaintext)
    return nonce + ct


def build_evidence_note(token, codes) -> str:
    ledger = "\n".join(
        f"{ord(ch):>3d} {codes[ch].replace('0', 'L').replace('1', 'R')}"
        for ch in sorted(codes, key=lambda c: ord(c)))
    return f"""\
================================================================
 LSPD IMPOUND LOT — RECOVERED FIELD NOTE  (CASE FTA-2026-1104)
 Vehicle: Declasse Voodoo (orange)   Evidence bag #4471
================================================================

The camera that took impound_camera.png had a second job. The
evidence techs call it "the matryoshka": every thing you open
hides another thing inside it. Work it layer by layer or not at
all. Everything you need to peel the doll is written below.

----------------------------------------------------------------
LAYER 1 — HOW THE PICTURE HIDES DATA
----------------------------------------------------------------
  * 2 LEAST-significant bits are buried in every colour channel.
  * Channels are visited R, then G, then B.
  * Pixels are read COLUMN by column (down a column, then the
    next column to the right).
  * Bits fill each byte most-significant-first.
  * The first 4 decoded bytes are a big-endian length, followed
    by that many bytes of an ENCRYPTED blob.
  * The same PNG carries EXIF GPS tags in its eXIf chunk. That
    location is the key material for layer 2.

----------------------------------------------------------------
LAYER 2 — FROM GPS TO A KEY
----------------------------------------------------------------
  * Recover latitude and longitude from the EXIF GPS tags.
  * Convert each to decimal degrees, then to a 10-digit code:

        a = round(abs(lat) * 10000) mod 100000
        b = round(abs(lon) * 10000) mod 100000
        CODE = zero-pad(a,5) + zero-pad(b,5)

    PASSPHRASE = "IMPOUND-" + CODE

  * Derive the stream key with PBKDF2-HMAC-SHA256:
        salt (hex)  = {PBKDF2_SALT.hex()}
        iterations  = {PBKDF2_ITER}
        dkLen       = 32          (AES-256)
  * Cipher: AES-256-CTR. The FIRST 16 bytes of the blob are the
    initial counter block; the rest is ciphertext.
  * The plaintext is itself a PNG file. Open it.

----------------------------------------------------------------
LAYER 3 — THE "MTX-1" MATRIX CODE (decoder description)
----------------------------------------------------------------
  The decrypted PNG is a black/white block grid: a home-made
  matrix code (no QR libraries were used). Layout of the module
  grid, which is {MATRIX_N} x {MATRIX_N} modules:
    - A 4-module WHITE quiet zone surrounds the code.
    - Row 0 and column 0 are SYNC ladders: the module at index i
      is BLACK when i is EVEN, WHITE when i is ODD. Read them to
      find the module size and the correct orientation (rotate
      the grid until both ladders match).
    - Every remaining module (x>=1 AND y>=1) carries one data
      bit, read ROW-MAJOR (y ascending, then x ascending).
    - The bit stream is byte-aligned MSB-first: the first 16 bits
      are a big-endian length L, then L ASCII characters.
  The decoded characters are the TOKEN for the next layer.

----------------------------------------------------------------
LAYER 4 — THE TOKEN IS NOT WHAT IT LOOKS LIKE
----------------------------------------------------------------
  The token is shaped exactly like URL-safe base64, and decodes
  to bytes without complaint. But those bytes are not text: they
  are a HUFFMAN BITSTREAM, most-significant-bit first.
    - The first 16 bits are a big-endian character count C.
    - The next bits are C Huffman symbols; decode them with the
      FLEET LEDGER below (route 'L' = bit 0, 'R' = bit 1; 'unit'
      is the ASCII chit number of the symbol).

  FLEET DISPATCH LEDGER  (unit : route)
[LEDGER-BEGIN]
{ledger}
[LEDGER-END]

  What tumbles out is code. Run it.

----------------------------------------------------------------
  "Every doll holds a smaller doll. Stop early and you go home
   with nothing but sawdust."
================================================================
"""


def main():
    out = L.out_dir("H03")

    # Layer 5 source -> Huffman (layer 4)
    src = build_source()
    codes = huffman_codes(src)
    bits = []
    for ch in src:
        bits += [int(b) for b in codes[ch]]
    stream = len(src).to_bytes(2, "big") + bits_to_bytes(bits)
    token = base64.urlsafe_b64encode(stream).decode("ascii")

    # Layer 3 matrix PNG (plaintext for layer 2), guarded to fit the matrix
    assert len(token) + 2 <= ((MATRIX_N - 1) ** 2) // 8, "token too big for MTX-1"
    matrix_png = matrix_png_bytes(token)

    # Layer 2 encrypt
    blob = encrypt_blob(matrix_png)

    # Layer 1 carrier + LSB + EXIF + decoys
    img = build_carrier()
    used = embed_lsb(img, blob)
    exif = build_exif("IMPOUND LOT CAM 3  plate-ref " + DECOYS["exif"])
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Software", "LSPD-Impound-CamSys v3.1")
    meta.add_text("Comment", "evidence bag #4471 — contents lighter than declared")
    meta.add_text("flag", DECOYS["text"])          # FALSE PATH A

    png_path = out / "impound_camera.png"
    img.save(png_path, "PNG", exif=exif, pnginfo=meta)

    # FALSE PATH C — trailing bytes after IEND
    with open(png_path, "ab") as f:
        f.write(b"\n--#IMPOUND-RECOVERY-SCRATCH--#\n"
                b"EVIDENCE_TAG=" + DECOYS["trail"].encode() +
                b"\n(disk sector dump; ignore)\n")

    note = build_evidence_note(token, codes)
    (out / "EVIDENCE_NOTE.txt").write_text(note, encoding="utf-8")

    # sanity: the real flag must never be written to the participant dir
    for p in out.iterdir():
        assert FLAG.encode() not in p.read_bytes(), f"flag leaked in {p.name}"

    print(f"[H03] carrier LSB payload = {used} bits")
    print(f"[H03] token ({len(token)} chars) -> matrix {MATRIX_N}x{MATRIX_N}")
    print(f"[H03] wrote {png_path.name} and EVIDENCE_NOTE.txt to {out}")


if __name__ == "__main__":
    main()
