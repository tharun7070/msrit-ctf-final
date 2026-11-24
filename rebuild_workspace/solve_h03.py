#!/usr/bin/env python3
"""H03 reference solver — peels all seven chained matryoshka shells.

Self-contained: it re-implements every decoder (gated LSB reader, EXIF/GPS
reader, PBKDF2 + AES-256-CTR, the PKZIP/ZipCrypto vault reader, AES-256-GCM,
the MTX-1 matrix code, the Huffman tree rebuilt from the note's frequency
table) from scratch and reads only the two participant files in
L.out_dir("H03").

Each shell is unlocked by a value recovered from a PRECEDING shell, so the
chain cannot be entered in the middle.
"""
import base64, io, re, struct, sys, zipfile
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
SALT_CTR = b"lspd-impound-2026"
SALT_GCM = b"evac-vault-7731"
ITER = 100000
TSIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1}

VAULT_OPEN = b"--#VAULT-BEGIN--#\n"
VAULT_CLOSE = b"\n--#VAULT-END--#\n"


# ---------------------------------------------------------------------------
# Shell 6 / note: frequency table -> deterministic Huffman tree
# ---------------------------------------------------------------------------
def parse_freq_table():
    note = (L.out_dir("H03") / "EVIDENCE_NOTE.txt").read_text(encoding="utf-8")
    block = re.search(r"\[LEDGER-BEGIN\]\n(.*?)\n\[LEDGER-END\]", note, re.S).group(1)
    freqs = {}
    for line in block.splitlines():
        line = line.strip()
        if not line:
            continue
        code, cnt = line.split()
        freqs[chr(int(code))] = int(cnt)
    return freqs


def build_codes(freqs):
    """Deterministic Huffman, identical to the generator: leaves inserted first
    in ascending ASCII order, internal nodes in creation order; ties by seq."""
    import heapq
    heap = []
    seq = 0
    for ch in sorted(freqs):
        heap.append([freqs[ch], seq, ch])
        seq += 1
    heapq.heapify(heap)
    if len(heap) == 1:
        return {heap[0][2]: "0"}
    while len(heap) > 1:
        a = heapq.heappop(heap)
        b = heapq.heappop(heap)
        heapq.heappush(heap, [a[0] + b[0], seq, (a[2], b[2])])
        seq += 1
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


def gating(freqs):
    d = len(freqs)
    t = sum(freqs.values())
    stride = (d % 7) + 2
    offset = t % stride
    return stride, offset


# ---------------------------------------------------------------------------
# Shell 1: gated column-major 2-LSB extraction
# ---------------------------------------------------------------------------
def extract_payload(stride, offset):
    img = Image.open(L.out_dir("H03") / "impound_camera.png").convert("RGB")
    px = img.load()
    bits = []
    slot = 0
    for x in range(W):
        for y in range(H):
            for c in px[x, y]:
                if slot % stride == offset:
                    bits.append((c >> 1) & 1)
                    bits.append(c & 1)
                slot += 1
    data = bytearray()
    for i in range(0, (len(bits) // 8) * 8, 8):
        data.append(int("".join(str(b) for b in bits[i:i + 8]), 2))
    n = int.from_bytes(data[:4], "big")
    payload = bytes(data[4:4 + n])
    return payload[:16], payload[16:]          # TAG, CTR_BLOB


# ---------------------------------------------------------------------------
# Shell 2: EXIF GPS reader (hand-rolled TIFF parse) + AES-256-CTR
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


def ctr_decrypt(blob, pwd):
    key = PBKDF2(pwd.encode(), SALT_CTR, dkLen=32, count=ITER, hmac_hash_module=SHA256)
    nonce, ct = blob[:16], blob[16:]
    return AES.new(key, AES.MODE_CTR, nonce=b"",
                   initial_value=int.from_bytes(nonce, "big")).decrypt(ct)


# ---------------------------------------------------------------------------
# Shell 3: read the password-gated ZIP from the trailing zone
# ---------------------------------------------------------------------------
def read_vault(badge):
    data = (L.out_dir("H03") / "impound_camera.png").read_bytes()
    z0 = data.index(VAULT_OPEN) + len(VAULT_OPEN)
    z1 = data.index(VAULT_CLOSE, z0)
    zf = zipfile.ZipFile(io.BytesIO(data[z0:z1]))
    zf.setpassword(badge.encode())
    return zf.read("layer4.bin")


# ---------------------------------------------------------------------------
# Shell 4: AES-256-GCM
# ---------------------------------------------------------------------------
def gcm_decrypt(blob, badge, code, tag):
    key = PBKDF2((badge + ":" + code).encode(), SALT_GCM,
                 dkLen=32, count=ITER, hmac_hash_module=SHA256)
    nonce = SHA256.new(b"gcm" + tag).digest()[:12]
    ct, gcm_tag = blob[:-16], blob[-16:]
    return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, gcm_tag)


# ---------------------------------------------------------------------------
# Shell 5: MTX-1 matrix decode
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
    for i in range(MATRIX_N):
        want = 1 if i % 2 == 0 else 0
        if grid[0, i] != want or grid[i, 0] != want:
            return False
    return True


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
# Shell 6: Huffman decode using the frequency table
# ---------------------------------------------------------------------------
def huffman_decode(stream, codes):
    rev = {v: k for k, v in codes.items()}
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
    # Shell 6 note gives both the Huffman tree and the LSB gating.
    freqs = parse_freq_table()
    codes = build_codes(freqs)
    stride, offset = gating(freqs)

    # Shell 1
    tag, ctr_blob = extract_payload(stride, offset)

    # Shell 2
    lat, _latref, lon, _lonref = read_gps()
    code = gps_code(lat, lon)
    badge = ctr_decrypt(ctr_blob, "IMPOUND-" + code).decode("ascii")
    assert badge, "empty badge"

    # Shell 3
    gcm_blob = read_vault(badge)

    # Shell 4
    matrix_png = gcm_decrypt(gcm_blob, badge, code, tag)
    assert matrix_png[:8] == b"\x89PNG\r\n\x1a\n", "shell4 plaintext is not a PNG"

    # Shell 5
    token = decode_matrix(matrix_png)
    assert re.fullmatch(r"[A-Za-z0-9_\-]+={0,2}", token), f"token shape off: {token!r}"

    # Shell 6
    stream = base64.urlsafe_b64decode(token)
    src = huffman_decode(stream, codes)

    # Shell 7
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
