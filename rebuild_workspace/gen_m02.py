#!/usr/bin/env python3
"""M02 — Airport Ghost Flight. Generator (private organizer tooling).

Produces `airport_traffic.pcap`: a classic little-endian pcap capture of real
raw TCP/IPv4 packets (real IPv4/TCP checksums via lib_fta.build_tcp_packet).
The TCP payloads carry a custom binary frame:

    frame = MAGIC(0xDEAD1A70, u32 LE) | type(u16 LE) | length(u16 LE)
            | payload(length bytes) | CRC32(u32 LE)
    CRC32 = zlib.crc32(MAGIC|type|length|payload) & 0xFFFFFFFF

Only frames whose CRC32 is *valid* AND whose type == 0x0A carry flag fragments.
For those frames the payload layout is:

    payload[0:6]   opaque channel/uptime header (free bytes)
    payload[6:10]  fragment sequence number (u32 LE)
    payload[10:]   fragment data bytes XOR (frame's 4 CRC32 bytes, repeated)

The stored data is XOR-masked with the frame's own CRC32 bytes, and the CRC32 is
computed over the whole frame body *including* that masked data.  That is a fixed
point (crc depends on the data, the data depends on crc).  We solve it exactly by
linear algebra over GF(2): zlib.crc32 is affine in its input bits, and the XOR
mask is linear in the crc bits, so `crc = g(crc)` becomes a solvable linear
system in 80 unknowns (6 free header bytes + 32 crc bits).

Decoys: some type==0x0A frames with a corrupted CRC32, and some frames with a
valid CRC32 but type != 0x0A.  Neither passes the gate.
"""
import random, struct, sys, zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

FLAG = L.FLAGS["M02"]
MAGIC = L.FRAME_MAGIC
TYPE_DATA = 0x0A
DECOY_TYPES = [0x01, 0x02, 0x0B, 0x0C, 0x0D]


# ---------------------------------------------------------------------------
# GF(2) linear solver (Gaussian elimination / RREF)
# ---------------------------------------------------------------------------
def gf2_solve(cols, target, n):
    """Find x (n-bit int) with XOR_{i: x_i=1} cols[i] == target.
    Returns an n-bit int or None if the system is inconsistent."""
    m = 32
    row_m = []
    row_r = []
    for r in range(m):
        mask = 0
        for i in range(n):
            if (cols[i] >> r) & 1:
                mask |= (1 << i)
        row_m.append(mask)
        row_r.append((target >> r) & 1)

    pivots = {}
    pr = 0
    for col in range(n):
        sel = -1
        for i in range(pr, m):
            if (row_m[i] >> col) & 1:
                sel = i
                break
        if sel < 0:
            continue
        row_m[pr], row_m[sel] = row_m[sel], row_m[pr]
        row_r[pr], row_r[sel] = row_r[sel], row_r[pr]
        for i in range(m):
            if i != pr and ((row_m[i] >> col) & 1):
                row_m[i] ^= row_m[pr]
                row_r[i] ^= row_r[pr]
        pivots[col] = pr
        pr += 1
        if pr == m:
            break

    for i in range(m):
        if row_m[i] == 0 and row_r[i] == 1:
            return None
    x = 0
    for col, ri in pivots.items():
        if row_r[ri]:
            x |= (1 << col)
    return x


def _mask_of(crc, length):
    """The 4 crc bytes (LE) repeated to `length` bytes."""
    cb = (crc & 0xFFFFFFFF).to_bytes(4, "little")
    return (cb * (length // 4 + 1))[:length]


def build_data_frame(chunk: bytes, seq: int) -> bytes:
    """Build a genuine type==0x0A frame carrying `chunk` at sequence `seq`,
    solving the crc/data XOR fixed point exactly."""
    length = len(chunk)
    head = struct.pack("<IHH", MAGIC, TYPE_DATA, 10 + length)
    seqb = struct.pack("<I", seq & 0xFFFFFFFF)
    zero6 = b"\x00" * 6

    def g(prefix6, crc):
        mask = _mask_of(crc, length)
        stored = bytes(a ^ b for a, b in zip(chunk, mask))
        body = head + prefix6 + seqb + stored
        return crc ^ (zlib.crc32(body) & 0xFFFFFFFF)

    t0 = g(zero6, 0)
    cols = []
    for p in range(48):  # free header bits
        pb = bytearray(zero6)
        pb[p // 8] ^= 1 << (p % 8)
        cols.append(g(bytes(pb), 0) ^ t0)
    for j in range(32):  # crc bits
        cols.append(g(zero6, 1 << j) ^ t0)

    x = gf2_solve(cols, t0, 80)
    assert x is not None, "fixed-point system inconsistent"
    prefix6 = bytearray(zero6)
    for p in range(48):
        if (x >> p) & 1:
            prefix6[p // 8] ^= 1 << (p % 8)
    crc = 0
    for j in range(32):
        if (x >> (48 + j)) & 1:
            crc |= 1 << j
    prefix6 = bytes(prefix6)
    assert g(prefix6, crc) == 0, "fixed point not satisfied"

    stored = bytes(a ^ b for a, b in zip(chunk, _mask_of(crc, length)))
    payload = prefix6 + seqb + stored
    body = head + payload
    assert (zlib.crc32(body) & 0xFFFFFFFF) == crc
    return body + struct.pack("<I", crc)


def _rand_payload(rnd, n):
    return bytes(rnd.randrange(256) for _ in range(n))


def build_decoy_crc_frame(rnd):
    """type==0x0A but a corrupted CRC32 -> must be rejected."""
    payload = _rand_payload(rnd, rnd.randint(12, 40))
    return L.frame(TYPE_DATA, payload, corrupt_crc=True)


def build_wrong_type_frame(rnd):
    """valid CRC32 but type != 0x0A -> must be rejected."""
    payload = _rand_payload(rnd, rnd.randint(8, 48))
    return L.frame(rnd.choice(DECOY_TYPES), payload)


def noise_line(rnd):
    return ("TELEMETRY NODE=TOWER-{} ALT={:05d} HDG={:03d} SPD={:03d} "
            "SEQ={:05d} STATUS={}\n").format(
                rnd.randint(1, 9), rnd.randint(0, 41000), rnd.randint(0, 359),
                rnd.randint(0, 320), rnd.randint(0, 99999),
                "OK" if rnd.random() < 0.8 else "DRIFT").encode("ascii")


def build_stream(src, dst, sport, dport, payloads, rnd):
    """SYN / SYN-ACK / ACK, then one packet per payload, then FIN-ACK."""
    pkts = []
    seq = rnd.randint(1000, 90000)
    ack = rnd.randint(1000, 90000)
    pkts.append(L.build_tcp_packet(src, dst, sport, dport, seq, 0, b"", 0x02))
    seq += 1
    pkts.append(L.build_tcp_packet(dst, src, dport, sport, ack, seq, b"", 0x12))
    ack += 1
    pkts.append(L.build_tcp_packet(src, dst, sport, dport, seq, ack, b"", 0x10))
    for p in payloads:
        pkts.append(L.build_tcp_packet(src, dst, sport, dport, seq, ack, p, 0x18))
        seq += len(p)
    pkts.append(L.build_tcp_packet(src, dst, sport, dport, seq, ack, b"", 0x11))
    return pkts


def main():
    out = L.out_dir("M02")
    rnd = random.Random(0x1A70C7)  # deterministic

    # ---- split the flag into fragments -------------------------------------
    sizes = [6, 6, 6, 5, 5, 5]
    chunks, i = [], 0
    for s in sizes:
        chunks.append(FLAG[i:i + s])
        i += s
    assert "".join(chunks) == FLAG

    seq_base = 4096
    frag_frames = []
    frag_meta = []
    for k, ch in enumerate(chunks):
        seq = seq_base + k
        fr = build_data_frame(ch.encode("ascii"), seq)
        frag_frames.append(fr)
        frag_meta.append((seq, ch))

    # ---- decoys -------------------------------------------------------------
    decoys = []
    for _ in range(3):
        decoys.append(build_decoy_crc_frame(rnd))
    for _ in range(3):
        decoys.append(build_wrong_type_frame(rnd))
    decoys.append(L.frame(rnd.choice(DECOY_TYPES), _rand_payload(rnd, 20),
                          corrupt_crc=True))

    # ---- TCP streams (airport tower theme) ---------------------------------
    streams = [
        ("10.20.30.2",  "10.20.30.10", 4001, 51000),  # tower uplink (flag)
        ("10.20.30.3",  "10.20.30.11", 4002, 51001),  # approach feed (decoys)
        ("10.20.30.7",  "10.20.30.2",  9000, 41000),  # radar sweep (noise)
        ("10.20.30.20", "10.20.30.3",  8080, 52000),  # ground ops (noise)
        ("10.20.30.11", "10.20.30.2",  5001, 33000),  # baggage scanners
        ("10.20.30.10", "10.20.30.7",  9100, 60000),  # refuel telemetry
    ]

    # decoys[0..2] = type 0x0A w/ corrupt CRC ; decoys[3..5] = valid CRC, bad
    # type ; decoys[6] = corrupt CRC + bad type.

    # stream 0: fragment frames shuffled among noise, plus one combined payload
    s0 = [noise_line(rnd) for _ in range(9)]
    shuffled_frags = list(frag_frames)
    rnd.shuffle(shuffled_frags)          # out of sequence order -> must sort
    for fr in shuffled_frags:
        s0.append(fr)
    # one TCP payload carrying two frames (both decoys) -> must walk frames
    s0.append(decoys[6] + decoys[0])
    rnd.shuffle(s0)

    # stream 1: decoy frames among noise, incl. a two-frame payload
    s1 = [noise_line(rnd) for _ in range(10)]
    s1 += [decoys[1] + decoys[2], decoys[3], decoys[4]]
    rnd.shuffle(s1)

    # stream 2: mostly noise + one decoy
    s2 = [noise_line(rnd) for _ in range(14)]
    s2 += [decoys[5]]
    rnd.shuffle(s2)

    s3 = [noise_line(rnd) for _ in range(21)]
    s4 = [noise_line(rnd) for _ in range(18)]
    s5 = [noise_line(rnd) for _ in range(16)]

    payload_sets = [s0, s1, s2, s3, s4, s5]

    packets = []
    for (src, dst, sp, dp), pl in zip(streams, payload_sets):
        packets.extend(build_stream(src, dst, sp, dp, pl, rnd))

    L.write_pcap(out / "airport_traffic.pcap", packets)

    # ---- MANIFEST.txt (no protocol spec) -----------------------------------
    manifest = (
        "AIRPORT TRAFFIC ARCHIVE — LSIA TOWER\n"
        "=====================================\n"
        "Captured: 2026-11-21T03:14:00Z   Operator: FTA SIGINT desk\n"
        "Source: span port on the runway telemetry switch (10.20.30.0/24).\n"
        "\n"
        "This file is a raw binary telemetry capture pulled straight off the\n"
        "tower wire: the airport keeps shipping its own little packets inside\n"
        "the ordinary network traffic. Nobody has given us the wire format.\n"
        "\n"
        "Not everything on the wire is intact, and not everything that is\n"
        "intact is worth reading. Trust the checksums. Read only what the\n"
        "tower is actually broadcasting, in the order the tower sent it.\n"
        "\n"
        "Deliverable: the flight callsign (the recovered flag).\n"
    )
    (out / "MANIFEST.txt").write_text(manifest, encoding="utf-8")

    print(f"[M02] wrote {len(packets)} packets -> {out/'airport_traffic.pcap'}")
    print(f"[M02] fragments = {len(frag_frames)}  decoys = {len(decoys)}")
    print(f"[M02] flag = {FLAG}")


if __name__ == "__main__":
    main()
