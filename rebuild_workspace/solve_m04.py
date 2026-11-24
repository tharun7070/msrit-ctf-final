#!/usr/bin/env python3
"""M04 - Underground XOR Radio. Reference solver.

Inverts the stacked layers:
  1. Parse the 12-byte CLEARTEXT sync header of radio_packet.bin to recover the
     ROUND-ROBIN STARTING LANE o, the burst length b and the beacon register's
     published (degree, taps).
  2. Unmask the surviving header prefix of keystream_sample.bin to expose the
     first REDACT_FROM bytes of the mask, then de-multiplex them into the three
     registers using the schedule r = (g + o) mod 3, where g = byte_index // b.
     Using the wrong o mixes bytes from different registers, so BM does not
     converge.
  3. Recover each register:
       * R0 and R1 (BM-recoverable): run Berlekamp-Massey on the register's bit
         stream and extend the recursion.
       * R2 (beacon): the sample exposes 40 < 2*23 bits -- too few for BM -- so
         instead solve the register's small linear output system over GF(2)
         using its published taps, recovering its seed state.
  4. Re-multiplex the three streams to rebuild the whole mask.
  5. Unmask radio_packet.bin, invert the 8-byte lane transpose, read the flag.

Prints "[M04] PASS -> <flag>".
"""
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

HEADER = ("LSPD EMERGENCY RADIO NET :: BEACON SYNC :: ALL UNITS COPY?"
          ).ljust(64, " ").encode()      # known plaintext (bytes)
REDACT_FROM = 15                          # leading sample/mask bytes exposed
BLOCK = 8                                 # lane transpose width

HDR_MAGIC = b"RDRX"
HDR_LEN = 12
BEACON = 2                                # beacon register index


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


# --- GF(2) linear tools (for the beacon register) ---------------------------
def state_outputs(state, taps, n):
    """Emit n output bits of the Fibonacci LFSR (same convention as
    lib_fta.lfsr_keystream) for the given initial state."""
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
    """Solve mat * x = rhs over GF(2). mat: list of rows (len deg); rhs: bits.
    Returns x (len deg). Assumes a unique solution exists."""
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
    """Recover the initial state of the beacon register from its known output
    bits by solving the register's linear output system over GF(2)."""
    deg = max(taps)
    n = len(known_bits)
    cols = [state_outputs(1 << j, taps, n) for j in range(deg)]
    mat = [[cols[j][t] for j in range(deg)] for t in range(n)]
    x = gf2_solve(mat, list(known_bits))
    seed = 0
    for j, bit in enumerate(x):
        seed |= (bit & 1) << j
    return seed


# --- multiplex schedule ------------------------------------------------------
def parse_header(pkt: bytes):
    assert pkt[:4] == HDR_MAGIC, "bad sync magic"
    ver, off, burst, bdeg = struct.unpack("<BBBB", pkt[4:8])
    mask = struct.unpack("<I", pkt[8:12])[0]
    taps = [t for t in range(mask.bit_length()) if (mask >> t) & 1]
    return off, burst, bdeg, taps


def lane_counts(n, burst, off):
    counts = [0, 0, 0]
    ng = (n + burst - 1) // burst
    for g in range(ng):
        counts[(g + off) % 3] += min(burst, n - g * burst)
    return counts


def demux(exposed: bytes, burst: int, off: int):
    """Split the exposed mask bytes into per-register streams (visit order)."""
    lanes = [[], [], []]
    for i, mb in enumerate(exposed):
        g = i // burst
        lanes[(g + off) % 3].append(mb)
    return lanes


def assign(n, streams, burst, off):
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


def recover_mask(sample: bytes, packet: bytes, n: int) -> bytes:
    """Layers 1-3: rebuild n bytes of mask from the surviving sample prefix."""
    off, burst, bdeg, btaps = parse_header(packet)

    exposed = bytes(s ^ h for s, h in zip(sample, HEADER))[:REDACT_FROM]
    lanes = demux(exposed, burst, off)                 # needs the header offset
    counts = lane_counts(n, burst, off)

    streams = [None, None, None]
    for r in (0, 1):
        bits = bytes_to_bits(bytes(lanes[r]))
        C, dd = berlekamp_massey(bits)
        streams[r] = bits_to_bytes(extend(bits, C, dd, counts[r] * 8))

    # beacon register: too few bits for BM -> solve the GF(2) linear system.
    known = bytes_to_bits(bytes(lanes[BEACON]))[:counts[BEACON] * 8]
    seed = recover_beacon_seed(known, btaps)
    streams[BEACON] = L.lfsr_keystream(seed, btaps, counts[BEACON])

    return assign(n, streams, burst, off)


def solve():
    out = L.out_dir("M04")
    sample = (out / "keystream_sample.bin").read_bytes()
    packet = (out / "radio_packet.bin").read_bytes()

    off, burst, bdeg, btaps = parse_header(packet)
    ct = packet[HDR_LEN:]

    mask = recover_mask(sample, packet, len(ct))
    masked = unpermute(ct)                 # undo the lane transpose first
    plaintext = bytes(p ^ k for p, k in zip(masked, mask))

    m = re.search(rb"FTA\{[^}]+\}", plaintext)
    assert m, f"no flag in decoded message: {plaintext!r}"
    flag = m.group(0).decode()
    assert flag == L.FLAGS["M04"], flag
    print(f"[M04] sync header: lane_off={off} burst={burst} "
          f"beacon_deg={bdeg} beacon_taps={btaps}")
    print("[M04] demuxed 3 lanes (BM x2, GF(2) linear solve x1 for beacon), "
          "rebuilt mask, inverted lane transpose")
    print("[M04] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
