#!/usr/bin/env python3
"""M04 - Underground XOR Radio. Reference solver.

Inverts the full real layer stack (all keyed off the cleartext 16-byte header):
  1. Parse radio_packet.bin's sync header: lane_off o, burst b, beacon degree
     and taps, MODE, SPIN key, WASH byte, CRC.
  2. Unmask the surviving sample prefix -> mask[0:15]; de-multiplex with
     r = (g + o) mod 3. Recover R0/R1 with Berlekamp-Massey and the deg-23
     beacon R2 by solving its small GF(2) output system with the published
     taps. Re-multiplex to rebuild the whole mask.
  3. ct = packet[16:].  Undo WASH (XOR the 16-byte header repeated), then undo
     SPIN (rotate each 16-byte span right by the header key), then undo the
     8-byte lane transpose, then XOR the mask.
  4. Read the payload; it carries the flag.

Prints "[M04] PASS -> <flag>".
"""
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

HEADER = ("LSPD EMERGENCY RADIO NET :: BEACON SYNC :: ALL UNITS COPY?"
          ).ljust(64, " ").encode()
REDACT_FROM = 15
BLOCK = 8
T2B = 16
HDR_MAGIC = b"RDRX"
HDR_LEN = 16
BEACON = 2


def bytes_to_bits(b):
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


def state_outputs(state, taps, n):
    deg = max(taps)
    bits = []
    st = state
    for _ in range(n):
        out = 0
        for t in taps:
            out ^= (st >> (deg - t)) & 1
        bits.append(st & 1)
        st = (st >> 1) | (out << (deg - 1))
    return bits


def gf2_solve(mat, rhs):
    rows = [row[:] + [bb] for row, bb in zip(mat, rhs)]
    ncols = len(mat[0])
    pivot_row = 0
    pivots = []
    for col in range(ncols):
        pr = None
        for r in range(pivot_row, len(rows)):
            if rows[r][col]:
                pr = r
                break
        if pr is None:
            continue
        rows[pivot_row], rows[pr] = rows[pr], rows[pivot_row]
        for r in range(len(rows)):
            if r != pivot_row and rows[r][col]:
                rows[r] = [a ^ c for a, c in zip(rows[r], rows[pivot_row])]
        pivots.append((pivot_row, col))
        pivot_row += 1
        if pivot_row == len(rows):
            break
    x = [0] * ncols
    for pr, col in pivots:
        x[col] = rows[pr][-1]
    return x


def recover_beacon_seed(known_bits, taps):
    deg = max(taps)
    n = len(known_bits)
    cols = [state_outputs(1 << j, taps, n) for j in range(deg)]
    mat = [[cols[j][t] for j in range(deg)] for t in range(n)]
    x = gf2_solve(mat, list(known_bits))
    seed = 0
    for j, bit in enumerate(x):
        seed |= (bit & 1) << j
    return seed


def taps_from_mask(mask):
    return [t for t in range(mask.bit_length()) if (mask >> t) & 1]


def parse_header(pkt):
    assert pkt[:4] == HDR_MAGIC, "bad sync magic"
    ver, off, burst, bdeg = struct.unpack("<BBBB", pkt[4:8])
    tmask = struct.unpack("<I", pkt[8:12])[0]
    mode, xk, flav = struct.unpack("<BBB", pkt[12:15])
    crc = pkt[15]
    ok = ((sum(pkt[:15]) ^ 0xA5) & 0xFF) == crc
    return dict(ver=ver, off=off, burst=burst, bdeg=bdeg, taps=taps_from_mask(tmask),
                mode=mode, xk=xk, flav=flav, crc=crc, crc_ok=ok)


def lane_counts(n, burst, nlanes, off):
    counts = [0] * nlanes
    ng = (n + burst - 1) // burst
    for g in range(ng):
        counts[(g + off) % nlanes] += min(burst, n - g * burst)
    return counts


def assign(n, streams, burst, off):
    nlanes = len(streams)
    ng = (n + burst - 1) // burst
    pos = [0] * nlanes
    out = bytearray(n)
    for g in range(ng):
        r = (g + off) % nlanes
        base = g * burst
        blk = min(burst, n - base)
        for j in range(blk):
            out[base + j] = streams[r][pos[r]]
            pos[r] += 1
    return bytes(out)


def demux(exposed, burst, off, nlanes):
    lanes = [[] for _ in range(nlanes)]
    for i, mb in enumerate(exposed):
        lanes[(i // burst + off) % nlanes].append(mb)
    return lanes


def build_mask_from_regs(n, regs, burst, off):
    counts = lane_counts(n, burst, len(regs), off)
    streams = [L.lfsr_keystream(seed, taps, counts[r])
               for r, (taps, seed) in enumerate(regs)]
    return assign(n, streams, burst, off)


def build_mask_from_sample(sample, n, burst, off, taps):
    exposed = bytes(s ^ h for s, h in zip(sample[:REDACT_FROM], HEADER[:REDACT_FROM]))
    lanes = demux(exposed, burst, off, 3)
    counts = lane_counts(n, burst, 3, off)
    streams = [None, None, None]
    for r in (0, 1):
        bits = bytes_to_bits(bytes(lanes[r]))
        C, dd = berlekamp_massey(bits)
        streams[r] = bits_to_bytes(extend(bits, C, dd, counts[r] * 8))
    known = bytes_to_bits(bytes(lanes[BEACON]))[:counts[BEACON] * 8]
    seed = recover_beacon_seed(known, taps)
    streams[BEACON] = L.lfsr_keystream(seed, taps, counts[BEACON])
    return assign(n, streams, burst, off)


def permutation(n, block=BLOCK):
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


def unpermute(data, block=BLOCK):
    n = len(data)
    perm = permutation(n, block)
    out = bytearray(n)
    for p in range(n):
        out[p] = data[perm[p]]
    return bytes(out)


def wash_stream(n, header):
    return bytes(header[i % len(header)] for i in range(n))


def unspin(data, span=T2B, k=0):
    """Inverse of gen's spin (right-rotate each span by k)."""
    out = bytearray(len(data))
    for base in range(0, len(data), span):
        blk = data[base:base + span]
        m = len(blk)
        kk = k % m if m else 0
        out[base:base + m] = (blk[m - kk:] + blk[:m - kk]) if kk else blk
    return bytes(out)


def decode(packet=None, force_off=None, force_taps=None, force_xk=None,
           skip_spin=False, skip_wash=False):
    out = L.out_dir("M04")
    if packet is None:
        packet = (out / "radio_packet.bin").read_bytes()
    sample = (out / "keystream_sample.bin").read_bytes()
    h = parse_header(packet)

    off = h["off"] if force_off is None else force_off
    taps = h["taps"] if force_taps is None else force_taps
    xk = h["xk"] if force_xk is None else force_xk
    ct = packet[HDR_LEN:]

    mask = build_mask_from_sample(sample, len(ct), h["burst"], off, taps)
    wash = b"\x00" * len(ct) if skip_wash else wash_stream(len(ct), packet[:HDR_LEN])
    spun = bytes(c ^ w for c, w in zip(ct, wash))
    transposed = spun if skip_spin else unspin(spun, T2B, xk)
    masked = unpermute(transposed)
    return bytes(p ^ k for p, k in zip(masked, mask))


def solve():
    out = L.out_dir("M04")
    packet = (out / "radio_packet.bin").read_bytes()
    h = parse_header(packet)
    pt = decode(packet)

    m = re.search(rb"FTA\{[^}]+\}", pt)
    assert m, f"no flag in decoded message: {pt!r}"
    flag = m.group(0).decode()
    assert flag == L.FLAGS["M04"], flag
    print(f"[M04] sync header: lane_off={h['off']} burst={h['burst']} "
          f"beacon_deg={h['bdeg']} taps={h['taps']} mode=0x{h['mode']:02X} "
          f"spin={h['xk']}/{T2B}B wash=header crc_ok={h['crc_ok']}")
    print("[M04] demuxed 3 lanes (BM x2, GF(2) linear solve x1 for beacon), "
          "rebuilt mask, undid WASH + SPIN + lane transpose")
    print("[M04] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
