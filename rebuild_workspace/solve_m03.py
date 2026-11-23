#!/usr/bin/env python3
"""M03 - LSPD Midnight Audit. Reference solver.

Pipeline:
  1. Walk lspd_auth.log recomputing each record's chain_hash from the
     PRECEDING STORED hash. Records whose recomputed hash differs are forged.
  2. Decode audit_delta.bin (custom RLE) and restore the original content of
     the forged records. Their stored chain_hash now matches -> chain sealed.
  3. Collect every event_code ending in "_ACCEPT" in file order, take the
     first character of each, XOR adjacent pairs -> flag.

Prints "[M03] PASS -> <flag>".
"""
import hashlib
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L


def sha256hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def read_log():
    text = (L.out_dir("M03") / "lspd_auth.log").read_text(encoding="utf-8")
    return [ln for ln in text.splitlines() if ln.strip()]


def find_breaks(lines):
    prev = "0" * 64
    breaks = []
    for idx, line in enumerate(lines):
        seq, ts, ec, data, h = line.split("|")
        if sha256hex(prev + f"{seq}|{ts}|{ec}|{data}") != h:
            breaks.append(idx)
        prev = h
    return breaks


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


def parse_delta(data: bytes) -> dict:
    assert data[:4] == b"AUD1", "bad delta magic"
    count = struct.unpack("<H", data[4:6])[0]
    off = 6
    out = {}
    for _ in range(count):
        seq = struct.unpack("<H", data[off:off + 2])[0]
        blen = struct.unpack("<I", data[off + 2:off + 6])[0]
        blob = data[off + 6:off + 6 + blen]
        out[seq] = rle_decode(blob).decode()
        off += 6 + blen
    return out


def repair(lines, delta):
    lines = list(lines)
    for idx in find_breaks(lines):
        seq, ts, ec, data, h = lines[idx].split("|")
        oseq, ots, oec, odata = delta[int(seq)].split("|")
        lines[idx] = f"{oseq}|{ots}|{oec}|{odata}|{h}"
    return lines


def decode_flag(lines):
    chars = [ln.split("|")[2][0] for ln in lines
             if ln.split("|")[2].endswith("_ACCEPT")]
    assert len(chars) % 2 == 0, f"odd ACCEPT count: {len(chars)}"
    return "".join(chr(ord(chars[i]) ^ ord(chars[i + 1]))
                   for i in range(0, len(chars), 2))


def solve():
    lines = read_log()
    delta = parse_delta((L.out_dir("M03") / "audit_delta.bin").read_bytes())
    breaks = find_breaks(lines)
    assert len(breaks) == 3, f"expected 3 forged records, found {len(breaks)}"
    repaired = repair(lines, delta)
    assert find_breaks(repaired) == [], "chain still broken after repair"
    flag = decode_flag(repaired)
    assert flag == L.FLAGS["M03"], flag
    print("[M03] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
