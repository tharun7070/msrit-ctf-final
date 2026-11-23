#!/usr/bin/env python3
"""M04 - Underground XOR Radio. Reference solver.

Pipeline:
  1. Unmask the known 64-byte header from keystream_sample.bin to expose the
     first 512 keystream bits (MSB-first within each byte).
  2. Run Berlekamp-Massey on those bits to recover the minimal LFSR feedback
     polynomial, and verify it reproduces the whole sample.
  3. Extend the recurrence over radio_packet.bin, unmask it, and extract the
     embedded FTA{...} payload.

Prints "[M04] PASS -> <flag>".
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

HEADER = "LSPD EMERGENCY RADIO NET :: CHANNEL 23 SYNC BEACON :: COPY?".ljust(64, " ")


def bytes_to_bits(b: bytes):
    bits = []
    for byte in b:
        for sh in range(7, -1, -1):
            bits.append((byte >> sh) & 1)
    return bits


def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, (len(bits) // 8) * 8, 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)


def berlekamp_massey(s):
    """BM over GF(2). Returns (C, L): C[0]==1 and s[n] = XOR C[j]*s[n-j] (j=1..L)."""
    C = [1]
    B = [1]
    L = 0
    m = 1
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
                L = i + 1 - L
                B = T
                m = 1
            else:
                m += 1
        else:
            m += 1
    return C[:L + 1], L


def extend(bits, C, L, n):
    r = list(bits)
    while len(r) < n:
        i = len(r)
        d = 0
        for j in range(1, L + 1):
            d ^= C[j] & r[i - j]
        r.append(d)
    return r


def solve():
    out = L.out_dir("M04")
    sample = (out / "keystream_sample.bin").read_bytes()
    packet = (out / "radio_packet.bin").read_bytes()

    exposed = bytes(s ^ h for s, h in zip(sample, HEADER.encode()))
    bits = bytes_to_bits(exposed)               # 512 known keystream bits
    C, deg = berlekamp_massey(bits)

    # verify the recovered generator reproduces the sample exactly
    regen = bits_to_bytes(extend(bits, C, deg, len(bits)))
    assert regen == exposed, "Berlekamp-Massey generator does not match sample"

    full_bits = extend(bits, C, deg, len(packet) * 8)
    keystream = bits_to_bytes(full_bits)
    plaintext = bytes(p ^ k for p, k in zip(packet, keystream))

    m = re.search(rb"FTA\{[^}]+\}", plaintext)
    assert m, f"no flag in decoded message: {plaintext!r}"
    flag = m.group(0).decode()
    assert flag == L.FLAGS["M04"], flag
    print(f"[M04] recovered LFSR: degree L={deg}, taps={C}")
    print("[M04] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
