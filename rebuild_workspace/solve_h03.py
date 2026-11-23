#!/usr/bin/env python3
"""H03 reference solver — walks all five matryoshka layers and prints the flag.

Self-contained: it re-implements every decoder (EXIF/GPS reader, PBKDF2 +
AES-256-CTR, the MTX-1 matrix code, the Huffman fleet ledger) from scratch and
reads only the two participant files in L.out_dir("H03").
"""
import base64, io, re, struct, sys
from pathlib import Path

import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

W, H = 200, 160          # carrier dimensions
MATRIX_N = 41            # MTX-1 module grid
TSIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1}


# ---------------------------------------------------------------------------
# Layer 1: column-major 2-LSB extraction
# ---------------------------------------------------------------------------
def extract_blob():
    img = Image.open(L.out_dir("H03") / "impound_camera.png").convert("RGB")
    px = img.load()
    bits = []
    for x in range(W):
        for y in range(H):
            for c in px[x, y]:
                bits.append((c >> 1) & 1)
                bits.append(c & 1)
    out = bytearray()
    for i in range(0, (len(bits) // 8) * 8, 8):
        out.append(int("".join(str(b) for b in bits[i:i + 8]), 2))
    n = int.from_bytes(out[:4], "big")
    return bytes(out[4:4 + n])


# ---------------------------------------------------------------------------
# EXIF GPS reader (hand-rolled TIFF parse)
# ---------------------------------------------------------------------------
def read_gps():
    raw = Image.open(L.out_dir("H03") / "impound_camera.png").info.get("exif")
    assert raw and raw[:6] == b"Exif\x00\x00", "no EXIF in PNG"
    tiff = raw[6:]
    assert tiff[:2] == b"II", "expected little-endian TIFF"
    off0 = struct.unpack("<I", tiff[4:8])[0]

    def ifd(off):
        n = struct.unpack("<H", tiff[off:off + 2])[0]
        res = {}
        for i in range(n):
            e = off + 2 + 12 * i
            tag, typ, count = struct.unpack("<HHI", tiff[e:e + 8])
            res[tag] = (typ, count, tiff[e + 8:e + 12])
        return res

    def payload(entry):
        typ, count, val4 = entry
        size = TSIZE[typ] * count
        if size <= 4:
            return val4[:size]
        o = struct.unpack("<I", val4)[0]
        return tiff[o:o + size]

    gps = ifd(struct.unpack("<I", ifd(off0)[0x8825][2])[0])

    def rationals(tag):
        typ, count, _ = gps[tag]
        data = payload(gps[tag])
        return [struct.unpack("<II", data[i * 8:i * 8 + 8]) for i in range(count)]

    def ref(tag):
        return payload(gps[tag]).split(b"\x00", 1)[0].decode()

    return (rationals(0x0002), ref(0x0001), rationals(0x0004), ref(0x0003))


def gps_code(lat, lon):
    def dec(dms):
        return dms[0][0] + dms[1][0] / 60 + (dms[2][0] / dms[2][1]) / 3600
    a = round(abs(dec(lat)) * 10000) % 100000
    b = round(abs(dec(lon)) * 10000) % 100000
    return f"{a:05d}{b:05d}"


# ---------------------------------------------------------------------------
# Layer 2: PBKDF2 + AES-256-CTR
# ---------------------------------------------------------------------------
def decrypt(blob, pwd):
    salt = b"lspd-impound-2026"
    key = PBKDF2(pwd.encode(), salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
    nonce, ct = blob[:16], blob[16:]
    return AES.new(key, AES.MODE_CTR, nonce=b"",
                   initial_value=int.from_bytes(nonce, "big")).decrypt(ct)


# ---------------------------------------------------------------------------
# Layer 3: MTX-1 matrix decode
# ---------------------------------------------------------------------------
def _extract_grid(img):
    arr = np.array(img.convert("L"))
    mask = arr < 128
    ys, xs = np.where(mask)
    y0, y1, x0, x1 = ys.min(), ys.max(), xs.min(), xs.max()
    content = arr[y0:y1 + 1, x0:x1 + 1]
    m = content.shape[0] // MATRIX_N
    grid = np.zeros((MATRIX_N, MATRIX_N), dtype=int)
    for gy in range(MATRIX_N):
        for gx in range(MATRIX_N):
            cy = int((gy + 0.5) * m)
            cx = int((gx + 0.5) * m)
            grid[gy, gx] = 1 if content[cy, cx] < 128 else 0
    return grid


def _sync_ok(grid):
    ok = True
    for i in range(MATRIX_N):
        want = 1 if i % 2 == 0 else 0
        if grid[0, i] != want or grid[i, 0] != want:
            ok = False
            break
    return ok


def decode_matrix(png_bytes):
    grid = _extract_grid(Image.open(io.BytesIO(png_bytes)))
    for k in range(4):
        g = np.rot90(grid, k)
        if _sync_ok(g):
            bits = []
            for y in range(1, MATRIX_N):
                for x in range(1, MATRIX_N):
                    bits.append(int(g[y, x]))
            data = bytearray()
            for i in range(0, (len(bits) // 8) * 8, 8):
                data.append(int("".join(str(b) for b in bits[i:i + 8]), 2))
            n = int.from_bytes(data[:2], "big")
            return bytes(data[2:2 + n]).decode("ascii")
    raise ValueError("MTX-1 sync ladders not found")


# ---------------------------------------------------------------------------
# Layer 4: Huffman decode using the "fleet ledger"
# ---------------------------------------------------------------------------
def parse_ledger():
    note = (L.out_dir("H03") / "EVIDENCE_NOTE.txt").read_text(encoding="utf-8")
    block = re.search(r"\[LEDGER-BEGIN\]\n(.*?)\n\[LEDGER-END\]", note, re.S).group(1)
    codes = {}
    for line in block.splitlines():
        line = line.strip()
        if not line:
            continue
        unit, route = line.split()
        codes[route.replace("L", "0").replace("R", "1")] = chr(int(unit))
    return codes


def huffman_decode(stream, codes):
    rev = codes  # bits -> char
    count = int.from_bytes(stream[:2], "big")
    bits = "".join(f"{b:08b}" for b in stream[2:])
    out = []
    cur = ""
    for bit in bits:
        cur += bit
        if cur in rev:
            out.append(rev[cur])
            cur = ""
            if len(out) == count:
                break
    assert len(out) == count, "huffman decode underrun"
    return "".join(out)


# ---------------------------------------------------------------------------
def solve():
    # Layer 1
    blob = extract_blob()

    # Layer 2
    lat, _latref, lon, _lonref = read_gps()
    pwd = "IMPOUND-" + gps_code(lat, lon)
    plaintext = decrypt(blob, pwd)
    assert plaintext[:8] == b"\x89PNG\r\n\x1a\n", "layer2 plaintext is not a PNG"

    # Layer 3
    token = decode_matrix(plaintext)
    assert re.fullmatch(r"[A-Za-z0-9_\-]+={0,2}", token), f"token shape off: {token!r}"

    # Layer 4
    codes = parse_ledger()
    stream = base64.urlsafe_b64decode(token)
    src = huffman_decode(stream, codes)

    # Layer 5
    buf = io.StringIO()
    import contextlib
    with contextlib.redirect_stdout(buf):
        exec(src, {})
    flag = re.search(r"FTA\{[a-z0-9_]+\}", buf.getvalue()).group(0)

    assert flag == L.FLAGS["H03"], flag
    print("[H03] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
