#!/usr/bin/env python3
"""H03 — Impound Evidence Matryoshka (7-layer, dependency-chained matryoshka).

Self-contained generator. Produces, in L.out_dir("H03"):
  * impound_camera.png  — participant carrier (gated LSB stego + EXIF GPS +
                          decoy metadata + trailing "vault" zone)
  * EVIDENCE_NOTE.txt   — field note describing EVERY layer (formulae only;
                          the passphrases are never written literally).

Design goal: a blanket extractor / naive automated solver must fail. Every
inner layer is unlocked by a value that only becomes available after a
PRECEDING layer has been peeled, so the chain cannot be entered in the middle.

Layer chain (outside -> inside):
  L1  GATED PNG LSB.  Only the channels whose linear index i satisfies
      i ≡ OFFSET (mod STRIDE) carry payload; STRIDE/OFFSET are derived
      arithmetically from the frequency table printed in the note. Every other
      channel is filled with bait, so a blanket column-major LSB dump yields a
      bogus flag.  Payload = LEN(4) || TAG(16) || CTR_blob.
  L2  AES-256-CTR (key = PBKDF2(passphrase_from_GPS, SALT_CTR)).  Its
      plaintext is the short "badge" string that keys the deeper layers.
  L3  Password-gated ZIP (legacy ZipCrypto) parked in the bytes AFTER IEND.
      The password IS the badge from L2.  Members: layer4.bin + bait.txt.
  L4  AES-256-GCM.  Key = PBKDF2(badge ":" gps_code).  Nonce = SHA256("gcm" ||
      TAG)[:12] (TAG recovered at L1).  Plaintext = the MTX-1 matrix PNG.
  L5  "MTX-1" home-made matrix code -> token.
  L6  The token looks like url-safe base64 but is a HUFFMAN bitstream; the
      tree is given ONLY as a frequency table in the note.
  L7  The Huffman output is Python that RECONSTRUCTS the flag via a small
      computation (XOR decode of a byte list) rather than printing a constant.

Private organizer tooling — never ship this file to participants.
"""
import base64, heapq, io, random, struct, sys, zlib
from pathlib import Path

import numpy as np
from PIL import Image, PngImagePlugin
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

# ---------------------------------------------------------------------------
# Fixed parameters (formulae are documented in EVIDENCE_NOTE.txt)
# ---------------------------------------------------------------------------
FLAG = L.FLAGS["H03"]

# EXIF GPS: (deg, min, sec_num, sec_den, ref)
GPS_LAT = (34, 3, 792, 100, "N")     # 34 deg 03' 07.92" N
GPS_LON = (118, 14, 3732, 100, "W")  # 118 deg 14' 37.32" W

SALT_CTR = b"lspd-impound-2026"      # PBKDF2 salt for L2 (AES-CTR)
SALT_GCM = b"evac-vault-7731"        # PBKDF2 salt for L4 (AES-GCM)
ITER = 100000
CARRIER_W, CARRIER_H = 200, 160
MATRIX_N = 41                        # MTX-1 grid is N x N modules
MODULE_PX = 6                        # pixels per module
QUIET = 4                            # quiet-zone width in modules

# L1 transport tag (16B). Its value feeds the L4 GCM nonce and appears nowhere
# in cleartext — it is buried in the gated LSB payload.
TAG = bytes.fromhex("a17f0c3d9b452e6812c4a90f73e1d5b8")
# L2 ciphertext initial counter block.
CTR_NONCE = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
# L2 plaintext: the badge that password-protects the trailing ZIP.
BADGE = "VAULT-K9-4471"

DECOYS = {
    "lsb":   "FTA{n41v3_l5b_str41ght_dump}",
    "png":   "FTA{l5b_pl41n_dump_b41t_7f}",
    "exif":  "FTA{3x1f_gps_tr4p_d3c0y}",
    "trail": "FTA{tr41l1ng_z0n3_d3c0y}",
    "zip":   "FTA{z1p_1nn3r_d3c0y}",
}

VAULT_OPEN = b"--#VAULT-BEGIN--#\n"
VAULT_CLOSE = b"\n--#VAULT-END--#\n"


# ---------------------------------------------------------------------------
# Hand-built EXIF (TIFF) with a GPS IFD — no piexif.
# ---------------------------------------------------------------------------
ASCII, SHORT, LONG, RATIONAL = 1, 3, 4, 5
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
# GPS -> passphrase (documented arithmetic over the DMS fields)
# ---------------------------------------------------------------------------
def _decimal(dms):
    deg, mn, sn, sd, _ref = dms
    return deg + mn / 60 + (sn / sd) / 3600


def gps_code() -> str:
    """10-digit code: last five digits of each scaled coordinate magnitude."""
    a = round(abs(_decimal(GPS_LAT)) * 10000) % 100000
    b = round(abs(_decimal(GPS_LON)) * 10000) % 100000
    return f"{a:05d}{b:05d}"


def ctr_passphrase() -> str:
    return "IMPOUND-" + gps_code()


def gcm_key() -> bytes:
    return PBKDF2((BADGE + ":" + gps_code()).encode(), SALT_GCM,
                  dkLen=32, count=ITER, hmac_hash_module=SHA256)


def gcm_nonce() -> bytes:
    return SHA256.new(b"gcm" + TAG).digest()[:12]


# ---------------------------------------------------------------------------
# Huffman (deterministic; described in the note as a FREQUENCY TABLE only)
# ---------------------------------------------------------------------------
def build_codes(freqs: dict):
    """Deterministic Huffman. Ties broken by insertion order: leaves are
    inserted in ascending ASCII order, internal nodes in creation order."""
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
    """L7: Python that RECONSTRUCTS the flag with a small computation."""
    x = 43
    data = [ord(c) ^ x for c in FLAG]
    return ("X=%d\n" % x
            + "d=[%s]\n" % ",".join(str(b) for b in data)
            + "print(''.join(chr(c^X) for c in d))\n")


def freq_table_text(codes, freqs) -> str:
    return "\n".join(f"{ord(ch):>3d} {freqs[ch]:>4d}"
                     for ch in sorted(freqs, key=ord))


def gating_from_freqs(freqs):
    """STRIDE = (distinct symbols) mod 7 + 2 ; OFFSET = (sum of counts) mod STRIDE."""
    d = len(freqs)
    t = sum(freqs.values())
    stride = (d % 7) + 2
    offset = t % stride
    return stride, offset


# ---------------------------------------------------------------------------
# Layer 5: MTX-1 matrix code (render)
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
# Layer 3: password-gated ZIP (legacy ZipCrypto; Python's zipfile cannot WRITE
# encrypted archives, so we emit the PKZIP structures ourselves).
# ---------------------------------------------------------------------------
def _dos_dt(y, mo, d, h, mi, s):
    dt = ((h & 0x1F) << 11) | ((mi & 0x3F) << 5) | ((s // 2) & 0x1F)
    dd = (((y - 1980) & 0x7F) << 9) | ((mo & 0xF) << 5) | (d & 0x1F)
    return dt, dd


def _crc_table():
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ (0xEDB88320 if (c & 1) else 0)
        table.append(c & 0xFFFFFFFF)
    return table


_CRC_TABLE = _crc_table()


def _raw_crc32(byte, crc):
    """Raw reflected CRC32 step used by the PKZIP traditional cipher (note:
    this is NOT the same as zlib.crc32(), which applies init/final xor)."""
    return ((crc >> 8) ^ _CRC_TABLE[(crc ^ byte) & 0xFF]) & 0xFFFFFFFF


def _zipcrypto_stream(data: bytes, password: bytes) -> bytes:
    """Encrypt `data` with PKZIP's traditional cipher (keys updated with the
    PLAINTEXT byte, per spec)."""
    k0, k1, k2 = 0x12345678, 0x23456789, 0x34567890

    def update(b):
        nonlocal k0, k1, k2
        k0 = _raw_crc32(b, k0)
        k1 = ((k1 + (k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k2 = _raw_crc32((k1 >> 24) & 0xFF, k2)

    for b in password:
        update(b)
    out = bytearray()
    for b in data:
        k = k2 | 2
        ks = ((k * (k ^ 1)) >> 8) & 0xFF
        out.append(b ^ ks)
        update(b)
    return bytes(out)


def build_zip(password: str, entries) -> bytes:
    """entries: list of (name, plaintext_bytes). Deterministic (fixed mtime)."""
    pw = password.encode()
    fixed_head = bytes.fromhex("5a3c9e0174b2d8f60c1a2b")   # 11 bytes (12th = check)
    assert len(fixed_head) == 11
    local_parts, central_parts = [], []
    offset = 0
    for name, data in entries:
        crc = zlib.crc32(data) & 0xFFFFFFFF
        co = zlib.compressobj(9, zlib.DEFLATED, -15)   # raw deflate (no zlib wrapper)
        comp = co.compress(data) + co.flush()
        header = fixed_head + bytes([(crc >> 24) & 0xFF])
        enc = _zipcrypto_stream(header + comp, pw)
        csize = len(enc)          # includes the 12-byte encryption header
        usize = len(data)
        nb = name.encode()
        dt, dd = _dos_dt(1980, 1, 1, 0, 0, 0)
        lh = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0x0001, 8,
                         dt, dd, crc, csize, usize, len(nb), 0) + nb
        local = lh + enc
        local_parts.append(local)
        ch = struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 0x0001,
                         8, dt, dd, crc, csize, usize, len(nb), 0, 0, 0, 0,
                         0, offset) + nb
        central_parts.append(ch)
        offset += len(local)
    cd = b"".join(central_parts)
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(entries),
                       len(entries), len(cd), offset, 0)
    return b"".join(local_parts) + cd + eocd


# ---------------------------------------------------------------------------
# Layer 1: carrier image + gated LSB
# ---------------------------------------------------------------------------
def build_carrier() -> Image.Image:
    """Synthetic impound-lot surveillance still (deterministic noise)."""
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


def embed_lsb(img, payload: bytes, stride: int, offset: int, bait: str) -> int:
    """Column-major, 2 LSB per channel. ONLY channels whose 0-based slot index
    satisfies slot % stride == offset carry payload bits; all other channels
    carry a repeating BAIT bitstream (so a blanket dump yields the bait)."""
    bait_bits = bytes_to_bits(bait.encode())
    blen = len(bait_bits)
    payload_bits = bytes_to_bits(payload)
    px = img.load()
    slot = 0
    pi = 0
    for x in range(CARRIER_W):
        for y in range(CARRIER_H):
            r, g, b = px[x, y]
            out = []
            for c in (r, g, b):
                bp = 2 * slot            # global bit position in the bait stream
                b1 = bait_bits[bp % blen]
                b2 = bait_bits[(bp + 1) % blen]
                if slot % stride == offset and pi < len(payload_bits):
                    b1 = payload_bits[pi]
                    b2 = payload_bits[pi + 1]
                    pi += 2
                out.append((c & 0xFC) | (b1 << 1) | b2)
                slot += 1
            px[x, y] = tuple(out)
    assert pi == len(payload_bits), "payload does not fit the gated slots"
    return pi


# ---------------------------------------------------------------------------
# Build the nested chain
# ---------------------------------------------------------------------------
def ctr_encrypt(plaintext: bytes) -> bytes:
    key = PBKDF2(ctr_passphrase().encode(), SALT_CTR, dkLen=32,
                 count=ITER, hmac_hash_module=SHA256)
    ct = AES.new(key, AES.MODE_CTR, nonce=b"",
                 initial_value=int.from_bytes(CTR_NONCE, "big")).encrypt(plaintext)
    return CTR_NONCE + ct


def gcm_encrypt(plaintext: bytes) -> bytes:
    cipher = AES.new(gcm_key(), AES.MODE_GCM, nonce=gcm_nonce())
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return ct + tag


def build_evidence_note(codes, freqs, stride, offset) -> str:
    table = freq_table_text(codes, freqs)
    return f"""\
================================================================
 LSPD IMPOUND LOT — RECOVERED FIELD NOTE  (CASE FTA-2026-1104)
 Vehicle: Declasse Voodoo (orange)   Evidence bag #4471
================================================================

The camera that took impound_camera.png had a second job. The
evidence techs call it "the matryoshka": every artefact you open
hides another one inside it. SEVEN shells, chained — each shell's
key depends on something you only recover from the shell before
it. You cannot start in the middle. Several artefacts are bait.

Everything is described below as arithmetic and structure only.
No secret is written here in the clear.

----------------------------------------------------------------
SHELL 1 — HOW THE PICTURE HIDES DATA  (gated)
----------------------------------------------------------------
  * 2 LEAST-significant bits are buried in every colour channel.
  * Channels are visited R, then G, then B; pixels are read
    COLUMN by column (down a column, then the next column right).
  * A channel slot is numbered by its 0-based position in that
    column-major scan. ONLY the slots whose index i satisfies

        i ≡ OFFSET  (mod STRIDE)

    carry the real payload. Every other slot is filled with a
    repeating BAIT string — a straight dump of all LSBs returns
    the bait, not the evidence.
  * STRIDE and OFFSET are not stored in the picture. Derive them
    from the FREQUENCY TABLE in Shell 6:
        D       = number of rows in the table
        T       = sum of the counts in the table
        STRIDE  = (D mod 7) + 2
        OFFSET  = T mod STRIDE
  * Reading the selected slots MSB-first gives: a 4-byte
    big-endian LEN, then LEN bytes. Those bytes are
        TAG(16) || CTR_BLOB
    TAG is a 16-byte transport tag you will need much later.
  * The same PNG carries EXIF GPS tags in its eXIf chunk; that
    location is the key material for Shell 2.

----------------------------------------------------------------
SHELL 2 — FROM GPS TO A KEY  (AES-256-CTR)
----------------------------------------------------------------
  * Recover latitude and longitude from the EXIF GPS tags.
  * Convert each to decimal degrees, then to a 10-digit code:

        a = round(abs(lat) * 10000) mod 100000
        b = round(abs(lon) * 10000) mod 100000
        CODE = zero-pad(a,5) + zero-pad(b,5)

    PASSPHRASE = "IMPOUND-" + CODE

  * Derive the key with PBKDF2-HMAC-SHA256:
        salt (hex)  = {SALT_CTR.hex()}
        iterations  = {ITER}
        dkLen       = 32          (AES-256)
  * Cipher: AES-256-CTR. The FIRST 16 bytes of CTR_BLOB are the
    initial counter block; the rest is ciphertext.
  * The plaintext is short ASCII: a VAULT BADGE string. It is the
    password of the archive in Shell 3 and part of the Shell 4 key.

----------------------------------------------------------------
SHELL 3 — THE VAULT IN THE TRAILING ZONE  (password ZIP)
----------------------------------------------------------------
  * After the PNG's IEND marker there is a scratch sector dump and
    then a block delimited by
        {VAULT_OPEN.decode().rstrip()}
        {VAULT_CLOSE.decode().strip()}
    The block is a ZIP archive (legacy PKZIP "ZipCrypto").
  * The archive password IS the badge recovered in Shell 2.
  * Member "layer4.bin" is the real cargo (an AES-GCM blob).
    Member "bait.txt" is a decoy — ignore it.
  * NOTE: ZipCrypto keys are seeded from the password; read the
    member with a normal ZIP reader after supplying the password.

----------------------------------------------------------------
SHELL 4 — AES-256-GCM  (nonce from an earlier shell)
----------------------------------------------------------------
  * The layer4.bin blob is  ciphertext || tag(16)  (tag = last 16 B).
  * GCM key via PBKDF2-HMAC-SHA256:
        salt (hex)  = {SALT_GCM.hex()}
        iterations  = {ITER}
        dkLen       = 32
        passphrase  = badge (Shell 3) + ":" + CODE (Shell 2)
  * GCM nonce = first 12 bytes of SHA256(b"gcm" || TAG),
    where TAG is the 16-byte transport tag from Shell 1.
  * The plaintext is itself a PNG: a black/white MTX-1 matrix code.

----------------------------------------------------------------
SHELL 5 — THE "MTX-1" MATRIX CODE
----------------------------------------------------------------
  The decrypted PNG is a black/white block grid ({MATRIX_N} x {MATRIX_N}
  modules, 4-module white quiet zone):
    - Row 0 and column 0 are SYNC ladders: module i is BLACK when
      i is EVEN, WHITE when i is ODD. Rotate the grid until both
      ladders match to fix orientation.
    - Every module with x>=1 AND y>=1 carries one data bit, read
      ROW-MAJOR (y ascending, then x ascending).
    - Bits are byte-aligned MSB-first: the first 16 bits are a
      big-endian length L, then L ASCII characters.
  The decoded characters are the TOKEN for Shell 6.

----------------------------------------------------------------
SHELL 6 — THE TOKEN IS NOT WHAT IT LOOKS LIKE  (Huffman)
----------------------------------------------------------------
  The token is shaped exactly like URL-safe base64 and decodes
  without complaint. But the bytes are a HUFFMAN BITSTREAM,
  most-significant-bit first:
    - The first 16 bits are a big-endian character count C.
    - The next bits are C Huffman symbols, decoded with the
      frequency table below. Route convention: left edge = bit 0,
      right edge = bit 1.
  Rebuild the tree from the FREQUENCIES ONLY (no code is given):
    * repeatedly merge the two lowest-frequency nodes;
    * on a frequency tie, prefer the node inserted earlier — leaves
      are inserted first in ascending ASCII order, internal nodes
      in creation order (this fully determines the tree).

  FREQUENCY TABLE  (ascii_code : count)
[LEDGER-BEGIN]
{table}
[LEDGER-END]

----------------------------------------------------------------
SHELL 7 — RUN IT
----------------------------------------------------------------
  What tumbles out of Shell 6 is Python source. It does NOT contain
  the flag as a literal: it reconstructs it with a tiny computation.
  Execute it and read what it prints.

----------------------------------------------------------------
  "Every doll holds a smaller doll. Stop early and you go home
   with nothing but sawdust."
================================================================
"""


def main():
    out = L.out_dir("H03")

    # Shell 7 source -> Shell 6 Huffman
    src = build_source()
    freqs = {}
    for ch in src:
        freqs[ch] = freqs.get(ch, 0) + 1
    codes = build_codes(freqs)
    stride, offset = gating_from_freqs(freqs)

    bits = []
    for ch in src:
        bits += [int(b) for b in codes[ch]]
    stream = len(src).to_bytes(2, "big") + bits_to_bytes(bits)
    token = base64.urlsafe_b64encode(stream).decode("ascii")
    assert len(token) + 2 <= ((MATRIX_N - 1) ** 2) // 8, "token too big for MTX-1"

    # Shell 5 matrix PNG (plaintext of Shell 4)
    matrix_png = matrix_png_bytes(token)

    # Shell 4 AES-256-GCM
    gcm_blob = gcm_encrypt(matrix_png)

    # Shell 3 password-gated ZIP (password = badge)
    zip_bytes = build_zip(BADGE, [("layer4.bin", gcm_blob),
                                  ("bait.txt", DECOYS["zip"].encode() + b"\n")])

    # Shell 2 AES-256-CTR (plaintext = badge)
    ctr_blob = ctr_encrypt(BADGE.encode())

    # Shell 1 payload = LEN(4) || TAG(16) || CTR_BLOB
    payload = TAG + ctr_blob
    lsb_payload = len(payload).to_bytes(4, "big") + payload

    # Shell 1 carrier + gated LSB + EXIF + decoy metadata + trailing vault
    img = build_carrier()
    used = embed_lsb(img, lsb_payload, stride, offset, DECOYS["lsb"])
    exif = build_exif("IMPOUND LOT CAM 3  plate-ref " + DECOYS["exif"])
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Software", "LSPD-Impound-CamSys v3.1")
    meta.add_text("Comment", "evidence bag #4471 — contents lighter than declared")
    meta.add_text("flag", DECOYS["png"])          # FALSE PATH A

    png_path = out / "impound_camera.png"
    img.save(png_path, "PNG", exif=exif, pnginfo=meta)

    # Trailing zone: scratch decoy + the password-gated ZIP vault
    trailing = (b"\n--#IMPOUND-RECOVERY-SCRATCH--#\n"
                b"EVIDENCE_TAG=" + DECOYS["trail"].encode() + b"\n"
                b"(disk sector dump; ignore)\n")
    with open(png_path, "ab") as f:
        f.write(trailing)
        f.write(VAULT_OPEN)
        f.write(zip_bytes)
        f.write(VAULT_CLOSE)

    note = build_evidence_note(codes, freqs, stride, offset)
    (out / "EVIDENCE_NOTE.txt").write_text(note, encoding="utf-8")

    # sanity: the real flag must never be written to the participant dir
    for p in out.iterdir():
        assert FLAG.encode() not in p.read_bytes(), f"flag leaked in {p.name}"

    print(f"[H03] freq table: D={len(freqs)} T={sum(freqs.values())} "
          f"-> STRIDE={stride} OFFSET={offset}")
    print(f"[H03] gated LSB payload = {used} bits ({len(lsb_payload)} bytes)")
    print(f"[H03] token ({len(token)} chars) -> matrix {MATRIX_N}x{MATRIX_N}; "
          f"zip vault = {len(zip_bytes)} bytes")
    print(f"[H03] wrote {png_path.name} and EVIDENCE_NOTE.txt to {out}")


if __name__ == "__main__":
    main()
