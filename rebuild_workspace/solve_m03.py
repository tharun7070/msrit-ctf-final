#!/usr/bin/env python3
"""M03 - LSPD Midnight Audit. Reference solver.

Pipeline:
  1. Recover the hidden 2-byte SALT by brute-forcing the 65536 candidate keys
     until the block-1 checkpoint root published in CHAIN_SPEC.txt matches.
  2. Walk lspd_auth.log recomputing each record's chain_hash (HMAC-SHA256 keyed
     by the salt) from the PRECEDING STORED hash. Records whose recomputed hash
     differs are forged. (Two forged entries sit in one checkpoint block and a
     third in another, so more than one block root is broken.)
  3. Decode the TRIPLY nested audit_delta.bin -- inverse columnar transpose,
     then undo the index-derived XOR, then RLE-decode -- and restore the
     original content of the forged records. The keyed chain and every block
     root then agree.
  4. Derive the flag: take every event_code ending exactly "_ACCEPT", classify
     each by the low bit of sha256(code)[0], and XOR the class-0 column of
     first characters with the class-1 column.

Prints "[M03] PASS -> <flag>".
"""
import hashlib
import hmac
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

BLOCK = 100
XOR_MUL = 0x5D
XOR_ADD = 0x1F
DELTA_MAGIC = b"AUD2"


def hmac_hex(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def content_of_line(ln: str) -> str:
    return "|".join(ln.split("|")[:4])


def code_class(ec: str) -> int:
    return int(hashlib.sha256(ec.encode()).hexdigest()[0], 16) & 1


def read_log():
    text = (L.out_dir("M03") / "lspd_auth.log").read_text(encoding="utf-8")
    return [ln for ln in text.splitlines() if ln.strip()]


def read_roots():
    text = (L.out_dir("M03") / "CHAIN_SPEC.txt").read_text(encoding="utf-8")
    roots = re.findall(r"digest=([0-9a-f]{64})", text)
    assert roots, "no checkpoint roots found in CHAIN_SPEC.txt"
    return roots


def block_msg(b: int, contents) -> bytes:
    return (f"block={b}|" + "".join(contents)).encode()


def recover_salt(lines, root1, salt_bytes=2) -> bytes:
    """Brute-force the hidden salt against the block-1 checkpoint root."""
    msg = block_msg(1, [content_of_line(ln) for ln in lines[:BLOCK]])
    for k in range(1 << (8 * salt_bytes)):
        key = k.to_bytes(salt_bytes, "big")
        if hmac_hex(key, msg) == root1:
            return key
    raise ValueError("salt not recovered")


def find_breaks(lines, key) -> list:
    prev = "0" * 64
    breaks = []
    for idx, line in enumerate(lines):
        content = content_of_line(line)
        if hmac_hex(key, (prev + content).encode()) != line.split("|")[4]:
            breaks.append(idx)
        prev = line.split("|")[4]
    return breaks


def verify_roots(lines, key, roots) -> bool:
    for b in range(1, len(roots) + 1):
        chunk = [content_of_line(ln) for ln in lines[(b - 1) * BLOCK:b * BLOCK]]
        if hmac_hex(key, block_msg(b, chunk)) != roots[b - 1]:
            return False
    return True


def rle_decode(blob: bytes) -> bytes:
    out = bytearray()
    i = 0
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


def _transpose_inv(t: bytes, w: int, n: int) -> bytes:
    rows = len(t) // w
    padded = bytearray(rows * w)
    idx = 0
    for c in range(w):
        for r in range(rows):
            padded[r * w + c] = t[idx]
            idx += 1
    return bytes(padded[:n])


def parse_delta(data: bytes) -> dict:
    assert data[:4] == DELTA_MAGIC, "bad delta magic"
    w = data[4]
    count = struct.unpack("<H", data[5:7])[0]
    off = 7
    out = {}
    for _ in range(count):
        seq = struct.unpack("<H", data[off:off + 2])[0]
        rlen = struct.unpack("<I", data[off + 2:off + 6])[0]
        blen = struct.unpack("<I", data[off + 6:off + 10])[0]
        blob = data[off + 10:off + 10 + blen]
        x = _transpose_inv(blob, w, rlen)
        r = bytes(b ^ ((i * XOR_MUL + XOR_ADD) & 0xFF) for i, b in enumerate(x))
        out[seq] = rle_decode(r).decode()
        off += 10 + blen
    return out


def repair(lines, delta, key) -> list:
    lines = list(lines)
    out = list(lines)
    for idx in find_breaks(lines, key):
        seq, ts, ec, data, h = lines[idx].split("|")
        oseq, ots, oec, odata = delta[int(seq)].split("|")
        out[idx] = f"{oseq}|{ots}|{oec}|{odata}|{h}"
    return out


def decode_flag(lines) -> str:
    evens, odds = [], []
    for ln in lines:
        ec = ln.split("|")[2]
        if ec.endswith("_ACCEPT"):
            (evens if code_class(ec) == 0 else odds).append(ec[0])
    assert len(evens) == len(odds), f"class columns uneven: {len(evens)}/{len(odds)}"
    return "".join(chr(ord(a) ^ ord(b)) for a, b in zip(evens, odds))


def solve():
    lines = read_log()
    roots = read_roots()
    key = recover_salt(lines, roots[0])
    delta = parse_delta((L.out_dir("M03") / "audit_delta.bin").read_bytes())

    breaks = find_breaks(lines, key)
    assert len(breaks) == 3, f"expected 3 forged records, found {len(breaks)}"
    assert not verify_roots(lines, key, roots), "block roots were not broken?"

    repaired = repair(lines, delta, key)
    assert find_breaks(repaired, key) == [], "chain still broken after repair"
    assert verify_roots(repaired, key, roots), "block roots still broken after repair"

    flag = decode_flag(repaired)
    assert flag == L.FLAGS["M03"], flag
    print("[M03] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
