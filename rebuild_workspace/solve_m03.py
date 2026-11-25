#!/usr/bin/env python3
"""M03 - LSPD Midnight Audit. Reference solver.

Pipeline:
  1. Bootstrap the salt schedule: brute-force the hidden 2-byte salt_1 against
     the published block-1 root, then derive salt_b = sha256("LSPD/chain-salt|"
     + root_{b-1})[:2] for every later block. One salt is NOT enough.
  2. Walk lspd_auth.log recomputing each record's chain_hash with its BLOCK's
     salt, from the PRECEDING STORED hash. Records whose recomputed hash differs
     are forged (three of them, spanning three checkpoint blocks).
  3. Decode region A of audit_delta.bin -- five layers, the last keyed by salt_1
     -- and restore the originals; the keyed chain and every block root agree.
  4. Decode region B, whose keystream is keyed by the last checkpoint root PLUS
     the original content of the last forged record (so it needs step 3 first),
     to obtain the flag mask.
  5. Predicate: take every event_code ending exactly "_ACCEPT", classify by the
     low bit of sha256(code)[0], XOR the class-0 column with the class-1 column
     -> the sealed token M. Flag = M XOR mask.

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
W = 7
XOR_MUL = 0x5D
XOR_ADD = 0x1F
MAGIC_A = b"AUD4"
MAGIC_B = b"AUDB"
DOM_SALT = b"LSPD/chain-salt|"
DOM_KA = b"AUD4-A|"
DOM_KB = b"AUD4-B|"


def hmac_hex(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def keystream(key: bytes, n: int) -> bytes:
    out = bytearray()
    ctr = 0
    while len(out) < n:
        out += hashlib.sha256(key + struct.pack("<I", ctr)).digest()
        ctr += 1
    return bytes(out[:n])


def rotr(b: int, r: int) -> int:
    return ((b >> r) | (b << (8 - r))) & 0xFF


def content_of_line(ln: str) -> str:
    return "|".join(ln.split("|")[:4])


def code_class(ec: str) -> int:
    return int(hashlib.sha256(ec.encode()).hexdigest()[0], 16) & 1


def block_msg(b: int, contents) -> bytes:
    return (f"block={b}|" + "".join(contents)).encode()


def derive_salt(prev_root: str) -> bytes:
    return hashlib.sha256(DOM_SALT + prev_root.encode()).digest()[:2]


def rot_of(root_last: str) -> int:
    return (int(root_last, 16) % 7) + 1


def read_log():
    text = (L.out_dir("M03") / "lspd_auth.log").read_text(encoding="utf-8")
    return [ln for ln in text.splitlines() if ln.strip()]


def read_roots():
    text = (L.out_dir("M03") / "CHAIN_SPEC.txt").read_text(encoding="utf-8")
    roots = re.findall(r"digest=([0-9a-f]{64})", text)
    assert roots, "no checkpoint roots found in CHAIN_SPEC.txt"
    return roots


def recover_bootstrap_salt(lines, root1, salt_bytes=2) -> bytes:
    msg = block_msg(1, [content_of_line(ln) for ln in lines[:BLOCK]])
    for k in range(1 << (8 * salt_bytes)):
        key = k.to_bytes(salt_bytes, "big")
        if hmac_hex(key, msg) == root1:
            return key
    raise ValueError("bootstrap salt not recovered")


def derive_salts(roots, bootstrap) -> list:
    salts = [bootstrap]
    for b in range(2, len(roots) + 1):
        salts.append(derive_salt(roots[b - 2]))
    return salts


def find_breaks(lines, salts) -> list:
    prev = "0" * 64
    breaks = []
    for idx, line in enumerate(lines):
        content = content_of_line(line)
        if hmac_hex(salts[idx // BLOCK], (prev + content).encode()) != line.split("|")[4]:
            breaks.append(idx)
        prev = line.split("|")[4]
    return breaks


def recompute_roots(lines, salts) -> list:
    roots = []
    for b in range(1, len(salts) + 1):
        chunk = [content_of_line(ln) for ln in lines[(b - 1) * BLOCK:b * BLOCK]]
        roots.append(hmac_hex(salts[b - 1], block_msg(b, chunk)))
    return roots


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


def decode_region_a_record(blob: bytes, raw_len: int, r: int, ka: bytes) -> str:
    # undo stage 5 (rotate-right), stage 4 (key XOR), stage 3 (transpose),
    # stage 2 (index XOR), stage 1 (RLE)
    x = bytes(rotr(b, r) for b in blob)
    ks = keystream(ka, len(x))
    x = bytes(b ^ k for b, k in zip(x, ks))
    x = _transpose_inv(x, W, raw_len)
    x = bytes(b ^ ((i * XOR_MUL + XOR_ADD) & 0xFF) for i, b in enumerate(x))
    return rle_decode(x).decode()


def parse_region_a(data: bytes, bootstrap, root_last) -> dict:
    assert data[:4] == MAGIC_A, "bad region-A magic"
    w = data[4]
    assert w == W, f"unexpected width {w}"
    count = struct.unpack("<H", data[5:7])[0]
    r = rot_of(root_last)
    ka = DOM_KA + bootstrap
    off = 7
    out = {}
    for _ in range(count):
        seq = struct.unpack("<H", data[off:off + 2])[0]
        rlen = struct.unpack("<I", data[off + 2:off + 6])[0]
        blen = struct.unpack("<I", data[off + 6:off + 10])[0]
        blob = data[off + 10:off + 10 + blen]
        out[seq] = decode_region_a_record(blob, rlen, r, ka)
        off += 10 + blen
    return out, off


def parse_region_b(data: bytes, off: int, root_last: str, last_original: str) -> bytes:
    assert data[off:off + 4] == MAGIC_B, "bad region-B magic"
    blen = struct.unpack("<H", data[off + 4:off + 6])[0]
    masked = data[off + 6:off + 6 + blen]
    kb = DOM_KB + root_last.encode() + b"|" + last_original.encode()
    return bytes(m ^ k for m, k in zip(masked, keystream(kb, len(masked))))


def repair(lines, originals) -> list:
    out = list(lines)
    for idx, ln in enumerate(lines):
        seq, _ts, _ec, _d, h = ln.split("|")
        if int(seq) in originals:
            out[idx] = f"{originals[int(seq)]}|{h}"
    return out


def predicate_token(lines) -> str:
    evens, odds = [], []
    for ln in lines:
        ec = ln.split("|")[2]
        if ec.endswith("_ACCEPT"):
            (evens if code_class(ec) == 0 else odds).append(ec[0])
    assert len(evens) == len(odds), f"class columns uneven: {len(evens)}/{len(odds)}"
    return "".join(chr(ord(a) ^ ord(b)) for a, b in zip(evens, odds))


def run_flags(lines, token: str) -> str:
    """Naive shortcut: adjacent-XOR over contiguous "<c>_<token>" runs."""
    groups, run, prev_seq = [], [], None
    for ln in lines:
        f = ln.split("|")
        seq, ec = int(f[0]), f[2]
        if ec.endswith("_" + token):
            if prev_seq is not None and seq != prev_seq + 1:
                groups.append(run)
                run = []
            run.append(ec[0])
            prev_seq = seq
        elif run:
            groups.append(run)
            run = []
            prev_seq = None
    if run:
        groups.append(run)
    return "".join("".join(chr(ord(r[i]) ^ ord(r[i + 1]))
                           for i in range(0, len(r) - 1, 2)) for r in groups)


def solve():
    lines = read_log()
    roots = read_roots()
    bootstrap = recover_bootstrap_salt(lines, roots[0])
    salts = derive_salts(roots, bootstrap)

    breaks = find_breaks(lines, salts)
    assert len(breaks) == 3, f"expected 3 forged records, found {len(breaks)}"
    blocks = sorted({(i // BLOCK) + 1 for i in breaks})
    assert len(blocks) >= 2, f"forgeries confined to one block: {blocks}"
    assert recompute_roots(lines, salts) != roots, "block roots were not broken?"

    delta = (L.out_dir("M03") / "audit_delta.bin").read_bytes()
    originals, off = parse_region_a(delta, bootstrap, roots[-1])

    last_original = originals[max(originals)]
    mask = parse_region_b(delta, off, roots[-1], last_original)

    repaired = repair(lines, originals)
    assert find_breaks(repaired, salts) == [], "chain still broken after repair"
    assert recompute_roots(repaired, salts) == roots, "block roots still broken"

    token = predicate_token(repaired)
    assert len(token) == len(mask), (len(token), len(mask))
    flag = bytes(ord(c) ^ m for c, m in zip(token, mask)).decode()
    assert flag == L.FLAGS["M03"], flag
    print("[M03] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
