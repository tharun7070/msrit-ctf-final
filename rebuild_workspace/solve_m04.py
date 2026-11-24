#!/usr/bin/env python3
"""M04 - Underground XOR Radio. Reference solver.

Inverts the stacked layers:
  1. Unmask the surviving (non-redacted) header prefix of keystream_sample.bin
     to expose the first REDACT_FROM bytes of the mask.
  2. De-multiplex the mask byte stream into its two lanes (even/odd bytes) and
     run Berlekamp-Massey on each lane separately. A single BM pass over the
     combined multiplexed stream does NOT converge within the exposed bit
     budget, so the split is required.
  3. Extend both lane recursions, re-multiplex to rebuild the whole mask.
  4. Unmask radio_packet.bin, invert the 8-byte lane transpose, read the flag.

Prints "[M04] PASS -> <flag>".
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

HEADER = ("LSPD EMERGENCY RADIO NET :: BEACON SYNC :: ALL UNITS COPY?"
          ).ljust(64, " ").encode()      # known plaintext (bytes)
REDACT_FROM = 38                          # leading sample/mask bytes exposed
BLOCK = 8                                 # lane transpose width


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


def permutation(n, block=BLOCK):
    """Lane transpose. Returns perm where payload[perm[p]] = masked[p]."""
    perm = [0] * n
    idx = 0
    nblocks = (n + block - 1) // block
    for j in range(block):
        for bb in range(nblocks):
            src = bb * block + j
            if src < n:
                perm[src] = idx
                idx += 1
    return perm


def permute(data, block=BLOCK):
    n = len(data)
    perm = permutation(n, block)
    out = bytearray(n)
    for p in range(n):
        out[perm[p]] = data[p]
    return bytes(out)


def unpermute(data, block=BLOCK):
    n = len(data)
    perm = permutation(n, block)
    out = bytearray(n)
    for p in range(n):
        out[p] = data[perm[p]]
    return bytes(out)


def recover_mask(sample: bytes, n: int) -> bytes:
    """Layers 1-3: rebuild n bytes of mask from the surviving sample prefix."""
    exposed = bytes(s ^ h for s, h in zip(sample, HEADER))[:REDACT_FROM]
    lane_a = exposed[0::2]                 # ALPHA byte stream
    lane_b = exposed[1::2]                 # BRAVO byte stream
    a_bits = bytes_to_bits(lane_a)
    b_bits = bytes_to_bits(lane_b)
    Ca, da = berlekamp_massey(a_bits)
    Cb, db = berlekamp_massey(b_bits)
    a = bits_to_bytes(extend(a_bits, Ca, da, ((n + 1) // 2) * 8))
    b = bits_to_bytes(extend(b_bits, Cb, db, (n // 2) * 8))
    out = bytearray(n)
    for j in range(n):
        out[j] = a[j // 2] if j % 2 == 0 else b[j // 2]
    return bytes(out)


def solve():
    out = L.out_dir("M04")
    sample = (out / "keystream_sample.bin").read_bytes()
    packet = (out / "radio_packet.bin").read_bytes()

    mask = recover_mask(sample, len(packet))
    masked = unpermute(packet)                 # undo the lane transpose first
    plaintext = bytes(p ^ k for p, k in zip(masked, mask))

    m = re.search(rb"FTA\{[^}]+\}", plaintext)
    assert m, f"no flag in decoded message: {plaintext!r}"
    flag = m.group(0).decode()
    assert flag == L.FLAGS["M04"], flag
    print("[M04] de-multiplexed two LFSR lanes, recovered both, inverted lane transpose")
    print("[M04] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
