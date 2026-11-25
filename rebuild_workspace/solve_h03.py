#!/usr/bin/env python3
"""H03 reference solver — peels all nine chained matryoshka shells.

Self-contained: it re-implements every decoder (EXIF/GPS reader, geo-gate
AES-256-CTR, gated+masked LSB reader, PKZIP/ZipCrypto vault reader,
AES-256-GCM with AAD, the MTX-1 matrix code, the Huffman tree rebuilt from the
note's frequency table, the sealed-source AES-256-CTR, and the token-gated
final stage) from scratch and reads only the shipped files in L.out_dir("H03").

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
MATRIX_N = 81            # MTX-1 module grid
SALT_GATE = b"impound-geogate-7"
SALT_CTR = b"lspd-impound-2026"
SALT_GCM = b"evac-vault-7731"
SALT_STAGE = b"matryoshka-seal"
ITER = 100000
TSIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1}

BAG_OPEN = b"--#EVIDENCE-BAG--#\n"
BAG_CLOSE = b"\n--#BAG-END--#\n"
VAULT_OPEN = b"--#VAULT-BEGIN--#\n"
VAULT_CLOSE = b"\n--#VAULT-END--#\n"

PNG = L.out_dir("H03") / "impound_camera.png"
NOTE = L.out_dir("H03") / "EVIDENCE_NOTE.txt"


# ---------------------------------------------------------------------------
# Shell 7 / note: frequency table -> deterministic Huffman tree (+ S2 gating)
# ---------------------------------------------------------------------------
def parse_freq_table():
    note = NOTE.read_text(encoding="utf-8")
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
# Shell 1: EXIF GPS reader (hand-rolled TIFF parse)
# ---------------------------------------------------------------------------
def read_gps():
    raw = Image.open(PNG).info.get("exif")
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


def read_gate_card(png_path):
    """S1: read the 'gate.card' tEXt value (hex), decrypt to the 16-byte mask."""
    im = Image.open(png_path)
    gate_hex = None
    for bag in (getattr(im, "text", None), im.info):
        if bag and "gate.card" in bag:
            gate_hex = bag["gate.card"]
            break
    assert gate_hex is not None, "gate.card chunk missing"
    blob = bytes.fromhex(gate_hex)
    nonce, ct = blob[:16], blob[16:]
    return nonce, ct


def gate_mask(gate_blob, code):
    nonce, ct = gate_blob
    key = PBKDF2(("GEO-" + code).encode(), SALT_GATE, dkLen=32,
                 count=ITER, hmac_hash_module=SHA256)
    return AES.new(key, AES.MODE_CTR, nonce=b"",
                   initial_value=int.from_bytes(nonce, "big")).decrypt(ct)


# ---------------------------------------------------------------------------
# Shell 2: gated + masked column-major 2-LSB extraction
# ---------------------------------------------------------------------------
def extract_payload(stride, offset, mask):
    img = Image.open(PNG).convert("RGB")
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
    masked = bytes(data[4:4 + n])
    payload = bytes(b ^ mask[i % 16] for i, b in enumerate(masked))
    return payload[:16], payload[16:]          # TAG, CTR_BLOB


# ---------------------------------------------------------------------------
# Shell 3: AES-256-CTR
# ---------------------------------------------------------------------------
def ctr_decrypt(blob, pwd, salt):
    key = PBKDF2(pwd.encode(), salt, dkLen=32, count=ITER, hmac_hash_module=SHA256)
    nonce, ct = blob[:16], blob[16:]
    return AES.new(key, AES.MODE_CTR, nonce=b"",
                   initial_value=int.from_bytes(nonce, "big")).decrypt(ct)


# ---------------------------------------------------------------------------
# Shell 4: read a password-gated ZIP from the trailing zone
# ---------------------------------------------------------------------------
def read_zip_block(open_m, close_m, password):
    data = PNG.read_bytes()
    z0 = data.index(open_m) + len(open_m)
    z1 = data.index(close_m, z0)
    zf = zipfile.ZipFile(io.BytesIO(data[z0:z1]))
    zf.setpassword(password.encode())
    return zf


# ---------------------------------------------------------------------------
# Shell 5: AES-256-GCM (nonce from the tag, AAD = mask)
# ---------------------------------------------------------------------------
def gcm_decrypt(blob, badge, code, tag, mask):
    key = PBKDF2((badge + ":" + code).encode(), SALT_GCM,
                 dkLen=32, count=ITER, hmac_hash_module=SHA256)
    nonce = SHA256.new(b"gcm" + tag).digest()[:12]
    ct, gcm_tag = blob[:-16], blob[-16:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(mask)
    return cipher.decrypt_and_verify(ct, gcm_tag)


# ---------------------------------------------------------------------------
# Shell 6: MTX-1 matrix decode
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
# Shell 7: Huffman decode using the frequency table
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
def walk_to_stage():
    """Peel S1..S8 and return (stage_source, seal_token) — the material the
    final stage (S9) needs. Used by both solve() and the validator."""
    # Note gives both the Huffman tree and the LSB gating.
    freqs = parse_freq_table()
    codes = build_codes(freqs)
    stride, offset = gating(freqs)

    # Shell 1: GPS -> CODE -> gate card -> MASK
    lat, _latref, lon, _lonref = read_gps()
    code = gps_code(lat, lon)
    mask = gate_mask(read_gate_card(PNG), code)
    assert len(mask) == 16, "gate mask wrong size"

    # Shell 2: gated + masked LSB -> TAG, CTR_BLOB
    tag, ctr_blob = extract_payload(stride, offset, mask)

    # Shell 3: AES-256-CTR -> BADGE
    badge = ctr_decrypt(ctr_blob, "IMPOUND-" + code, SALT_CTR).decode("ascii")
    assert badge, "empty badge"

    # Shell 4: real vault (password = badge) -> layer4.bin
    zf = read_zip_block(VAULT_OPEN, VAULT_CLOSE, badge)
    gcm_blob = zf.read("layer4.bin")

    # Shell 5: AES-256-GCM (AAD = mask)
    matrix_png = gcm_decrypt(gcm_blob, badge, code, tag, mask)
    assert matrix_png[:8] == b"\x89PNG\r\n\x1a\n", "shell5 plaintext is not a PNG"

    # Shell 6: MTX-1 matrix -> ROUTE_KEY | base64url(STREAM)
    combined = decode_matrix(matrix_png)
    route_key, b64stream = combined.split("|", 1)
    assert re.fullmatch(r"[A-Za-z0-9_\-]+", route_key), f"route key shape off: {route_key!r}"
    stream = base64.urlsafe_b64decode(b64stream)

    # Shell 7: Huffman -> SEAL_TOKEN | base64(SEALED_SOURCE)
    s7_text = huffman_decode(stream, codes)
    seal_token, b64sealed = s7_text.split("|", 1)
    sealed = base64.b64decode(b64sealed)

    # Shell 8: AES-256-CTR (key from ROUTE_KEY) -> Python source
    src = ctr_decrypt(sealed, route_key, SALT_STAGE).decode("utf-8")
    assert "hashlib" in src, "shell8 plaintext is not the expected stage"
    return src, seal_token


def run_stage(src, token):
    """S9: execute the recovered stage with `token` as sys.argv[1]."""
    buf = io.StringIO()
    import contextlib
    old_argv = sys.argv
    sys.argv = ["stage.py", token]
    try:
        with contextlib.redirect_stdout(buf):
            exec(src, {})
    finally:
        sys.argv = old_argv
    return buf.getvalue()


def solve(verbose=False):
    src, seal_token = walk_to_stage()

    # Shell 9: run the stage with the SEAL token as argv[1]
    out = run_stage(src, seal_token)
    m = re.search(r"FTA\{[a-z0-9_]+\}", out)
    assert m, f"final stage produced no flag: {out!r}"
    flag = m.group(0)

    assert flag == L.FLAGS["H03"], flag
    if verbose:
        print("[H03] seal_token =", seal_token)
        print("[H03] stage source:\n" + src)
    print("[H03] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve(verbose="-v" in sys.argv)
