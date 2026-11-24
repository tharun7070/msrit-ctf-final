#!/usr/bin/env python3
"""M02 — Airport Ghost Flight. Generator (private organizer tooling).

Produces `airport_traffic.pcap`: a classic little-endian pcap capture of real
raw IP packets (real IPv4/TCP checksums via lib_fta.build_tcp_packet).
Everything must be inverted, IN ORDER, to recover the flag:

1. IPv4 FRAGMENTATION — every data-bearing TCP datagram is split across
   several IPv4 fragments (MF flag + fragment offset + shared IP id).  A naive
   packet-by-packet parser never sees a complete TCP segment: frames only
   appear once the datagrams are REASSEMBLED first.

2. SESSION layer — the TCP payloads carry a NESTED two-layer binary protocol.

OUTER layer — the "tower seal frame" (all fields little-endian):

    off  0  OUTER_MAGIC = 0xDEAD1A70 (u32 LE)
    off  4  otype   (u16 LE)     -- 0x0A = telemetry broadcast
    off  6  olen    (u16 LE)
    off  8  oseq    (u32 LE)     -- RED-HERRING ordering field
    off 12  route   (u16 LE)     -- the "hole": NOT covered by the seal
    off 14  payload (olen bytes) -- contains ONE nested inner frame
    tail    seal    (u32 LE)

    seal = CRC32( frame[0:12] || payload )   # route bytes [12:14] skipped

The seal is a CRC32 over a SUBSET of the frame: everything up to oseq plus the
payload, but NOT the 2-byte `route` field sitting between them.  A naive
whole-frame CRC32 (over frame[0:14] || payload) therefore FAILS on genuine
frames, and frames sealed with that naive rule FAIL the genuine rule.

SESSION NONCE — the flag keystream is keyed by a per-session nonce that is NOT
repeated on every frame: it rides in PLAINTEXT at the front of the FIRST
genuine frame's payload only, as

    SESSION_MAGIC (u32 LE) | nonce (u32 LE) | inner frame ...

so the capture must be walked in order and the nonce harvested before any
fragment can be unmasked.

INNER layer — the "flight frame" (a DIFFERENT magic):

    off  0  INNER_MAGIC = 0x1A70C0DE (u32 LE)
    off  4  version (u8)
    off  5  itype   (u8)         -- 0x5C = flag fragment
    off  6  iseq    (u32 LE)     -- the REAL ordering field
    off 10  ilen    (u16 LE)
    off 12  masked fragment bytes -- data XOR keystream(nonce, iseq)

The fragment bytes are masked with a keystream derived from the SESSION NONCE
and the INNER sequence number (a Numerical-Recipes LCG), NOT from any CRC
bytes, so the old "XOR with the CRC bytes" trick yields garbage.  Fragments
must be ordered by the INNER sequence; the OUTER oseq is a decoy.

Decoys stacked in:
  * a fully-valid-looking group whose frames pass a NAIVE whole-frame CRC32 but
    fail the genuine (subset) seal — trusting the whole-frame checksum makes
    you accept this group, which reassembles to a plausible WRONG FTA{...} flag;
  * frames with corrupted seals;
  * frames with a genuine seal but a wrong OUTER type;
  * frames with a genuine seal but a wrong INNER type / version / magic.
"""
import random, struct, sys, zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

FLAG = L.FLAGS["M02"]
FAKE_FLAG = "FTA{n41v3_crc32_gh0st_p1l0t_sp00f}"

OUTER_MAGIC = L.FRAME_MAGIC               # 0xDEAD1A70
INNER_MAGIC = 0x1A70C0DE                  # must differ from OUTER_MAGIC
SESSION_MAGIC = 0x5E5510A5                # plaintext nonce block marker
OUTER_TYPE_DATA = 0x0A
OUTER_TYPE_DECOYS = [0x0B, 0x0C, 0x0D, 0x01, 0x0E]
INNER_VER = 1
INNER_TYPE_FRAG = 0x5C
INNER_TYPE_OTHER = 0x11
INNER_MAGIC_BAD = 0x0BADF00D

OUTER_HDR = 14          # bytes before the outer payload (incl. route)
ROUTE_OFF = 12          # 2-byte field excluded from the seal


# ---------------------------------------------------------------------------
# per-session nonce + (nonce, sequence)-keyed keystream (Numerical-Recipes LCG)
# ---------------------------------------------------------------------------
def keystream(nonce: int, seq: int, n: int) -> bytes:
    state = ((seq * 0x9E3779B1) ^ nonce ^ 0xA5A5A5A5) & 0xFFFFFFFF
    out = bytearray(n)
    for i in range(n):
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        out[i] = (state >> 24) & 0xFF
    return bytes(out)


def apply_mask(data: bytes, nonce: int, seq: int) -> bytes:
    return bytes(a ^ b for a, b in zip(data, keystream(nonce, seq, len(data))))


def session_prefix(nonce: int) -> bytes:
    """Plaintext session header carried ONLY by the first genuine frame."""
    return struct.pack("<II", SESSION_MAGIC, nonce)


# ---------------------------------------------------------------------------
# frame builders
# ---------------------------------------------------------------------------
def outer_seal(header12: bytes, payload: bytes) -> int:
    """Genuine seal: CRC32 over header[0:12] || payload (route bytes skipped)."""
    crc = zlib.crc32(header12)
    crc = zlib.crc32(payload, crc)
    return crc & 0xFFFFFFFF


def build_inner(nonce, iseq, data, itype=INNER_TYPE_FRAG, ver=INNER_VER, magic=INNER_MAGIC):
    masked = apply_mask(data, nonce, iseq)
    return struct.pack("<IBBIH", magic, ver, itype, iseq, len(masked)) + masked


def build_outer(payload, otype=OUTER_TYPE_DATA, oseq=0, route=0x1357,
                seal_mode="real", seal_value=None):
    olen = len(payload) & 0xFFFF
    header = struct.pack("<IHH", OUTER_MAGIC, otype, olen) + struct.pack("<I", oseq)
    body = header + struct.pack("<H", route) + payload      # full frame, no seal
    if seal_value is not None:
        seal = seal_value & 0xFFFFFFFF
    elif seal_mode == "naive":
        seal = zlib.crc32(body) & 0xFFFFFFFF                 # WRONG scope
    else:                                                    # "real"
        seal = outer_seal(header, payload)
    return body + struct.pack("<I", seal)


def _outer_parts(fr: bytes):
    """Return (header12, payload, real_seal, naive_seal) for an outer frame."""
    olen = struct.unpack("<H", fr[6:8])[0]
    header = fr[0:12]
    payload = fr[14:14 + olen]
    body = fr[:-4]
    return header, payload, outer_seal(header, payload), zlib.crc32(body) & 0xFFFFFFFF


def split_flag(flag, n=6):
    base, rem = divmod(len(flag), n)
    out, pos = [], 0
    for i in range(n):
        sz = base + (1 if i < rem else 0)
        out.append(flag[pos:pos + sz])
        pos += sz
    return out


# ---------------------------------------------------------------------------
# genuine fragments
# ---------------------------------------------------------------------------
def genuine_fragment_frames(rnd, nonce):
    chunks = split_flag(FLAG)
    assert "".join(chunks) == FLAG
    base = 0x2A00
    frames = []
    for k, ch in enumerate(chunks):
        iseq = base + k * 0x11
        oseq = rnd.randint(0, 0xFFFFFFFF)        # red herring
        route = rnd.randint(1, 0xFFFF)           # excluded-from-seal field
        inner = build_inner(nonce, iseq, ch.encode("ascii"))
        # the session nonce rides (plaintext) in the FIRST genuine frame only
        payload = (session_prefix(nonce) + inner) if k == 0 else inner
        fr = build_outer(payload, OUTER_TYPE_DATA, oseq, route, "real")
        _h, _p, real, naive = _outer_parts(fr)
        # genuine frames: real seal valid, naive whole-frame CRC must differ
        assert real == struct.unpack("<I", fr[-4:])[0]
        assert naive != real, "route bytes failed to perturb CRC"
        frames.append(fr)
    return frames


# ---------------------------------------------------------------------------
# decoys
# ---------------------------------------------------------------------------
def naive_seal_frames(rnd, nonce):
    """Fully-valid-looking group that reassembles to a plausible WRONG flag.
    Sealed with the NAIVE whole-frame CRC32, so a solver using the wrong CRC
    scope ACCEPTS them; the genuine subset rule REJECTS them.  Its first frame
    carries the same session nonce (same session)."""
    chunks = split_flag(FAKE_FLAG)
    assert "".join(chunks) == FAKE_FLAG
    base = 0x7100
    frames = []
    for k, ch in enumerate(chunks):
        iseq = base + k * 0x11
        oseq = rnd.randint(0, 0xFFFFFFFF)
        route = rnd.randint(1, 0xFFFF)
        inner = build_inner(nonce, iseq, ch.encode("ascii"))
        payload = (session_prefix(nonce) + inner) if k == 0 else inner
        fr = build_outer(payload, OUTER_TYPE_DATA, oseq, route, "naive")
        _h, _p, real, naive = _outer_parts(fr)
        assert naive == struct.unpack("<I", fr[-4:])[0]
        assert real != naive, "naive group would pass the genuine rule"
        frames.append(fr)
    return frames


def bad_seal_frames(rnd, nonce):
    """Genuine magic/type but a corrupted seal -> rejected."""
    out = []
    for i in range(4):
        iseq = 0x9000 + i * 0x11
        data = bytes(rnd.randrange(65, 91) for _ in range(rnd.randint(3, 9)))
        inner = build_inner(nonce, iseq, data)
        fr = build_outer(inner, OUTER_TYPE_DATA, rnd.randint(0, 0xFFFFFFFF),
                         rnd.randint(1, 0xFFFF), "real")
        seal = struct.unpack("<I", fr[-4:])[0]
        seal ^= 0x00FF0000 if (i & 1) else 0x0000FFFF
        out.append(fr[:-4] + struct.pack("<I", seal & 0xFFFFFFFF))
    return out


def wrong_outer_type_frames(rnd, nonce):
    """Genuine seal + inner fragment, but a wrong OUTER type -> rejected."""
    out = []
    for i in range(3):
        iseq = 0x9A00 + i * 0x11
        data = bytes(rnd.randrange(97, 123) for _ in range(5))
        inner = build_inner(nonce, iseq, data)
        fr = build_outer(inner, rnd.choice(OUTER_TYPE_DECOYS),
                         rnd.randint(0, 0xFFFFFFFF), rnd.randint(1, 0xFFFF), "real")
        out.append(fr)
    return out


def wrong_inner_frames(rnd, nonce):
    """Genuine outer frame + seal, but a wrong INNER type / version / magic."""
    out = []
    for i in range(2):
        iseq = 0x9B00 + i * 0x11
        inner = build_inner(nonce, iseq, bytes(rnd.randrange(48, 58) for _ in range(4)),
                            itype=INNER_TYPE_OTHER)
        fr = build_outer(inner, OUTER_TYPE_DATA, rnd.randint(0, 0xFFFFFFFF),
                         rnd.randint(1, 0xFFFF), "real")
        out.append(fr)
    # one with a completely foreign inner magic
    inner = struct.pack("<IBBIH", INNER_MAGIC_BAD, 1, INNER_TYPE_FRAG, 0x9B10, 4) \
        + b"\x01\x02\x03\x04"
    fr = build_outer(inner, OUTER_TYPE_DATA, rnd.randint(0, 0xFFFFFFFF),
                     rnd.randint(1, 0xFFFF), "real")
    out.append(fr)
    return out


# ---------------------------------------------------------------------------
# noise + IPv4 fragmentation + TCP streams
# ---------------------------------------------------------------------------
def noise_line(rnd):
    return ("TELEMETRY NODE=TOWER-{} ALT={:05d} HDG={:03d} SPD={:03d} "
            "SEQ={:05d} STATUS={}\n").format(
                rnd.randint(1, 9), rnd.randint(0, 41000), rnd.randint(0, 359),
                rnd.randint(0, 320), rnd.randint(0, 99999),
                "OK" if rnd.random() < 0.8 else "DRIFT").encode("ascii")


class _IdGen:
    """Hands out unique IPv4 identification values (one per datagram)."""

    def __init__(self, start=0x1000):
        self.v = start

    def next(self):
        ident = self.v & 0xFFFF
        self.v = (self.v + 1) & 0xFFFF
        return ident


_ID = _IdGen()


def _set_ip_id(pkt: bytes, ident: int) -> bytes:
    hdr = bytearray(pkt[:20])
    struct.pack_into("!H", hdr, 4, ident & 0xFFFF)   # identification
    struct.pack_into("!H", hdr, 10, 0)               # checksum = 0
    struct.pack_into("!H", hdr, 10, L._ip_checksum(bytes(hdr)))
    return bytes(hdr) + pkt[20:]


def ip_fragmentize(pkt: bytes, rnd) -> list:
    """Split a full IPv4 datagram into IPv4 fragments (MF + offset + ids)."""
    payload = pkt[20:]                       # TCP header + data
    assert payload, "refusing to fragment an empty datagram"
    ident = _ID.next()
    chunk_size = 8 * rnd.randint(2, 6)       # 16..48 bytes, a multiple of 8
    frags = []
    off = 0
    n = len(payload)
    while off < n:
        chunk = payload[off:off + chunk_size]
        last = (off + len(chunk)) >= n
        flags_off = (0x0000 if last else 0x2000) | ((off // 8) & 0x1FFF)
        hdr = bytearray(pkt[:20])
        struct.pack_into("!H", hdr, 2, 20 + len(chunk))     # total length
        struct.pack_into("!H", hdr, 4, ident)               # identification
        struct.pack_into("!H", hdr, 6, flags_off)           # flags + frag offset
        struct.pack_into("!H", hdr, 10, 0)
        struct.pack_into("!H", hdr, 10, L._ip_checksum(bytes(hdr)))
        frags.append(bytes(hdr) + chunk)
        off += len(chunk)
    return frags


def build_stream(src, dst, sport, dport, payloads, rnd):
    """SYN / SYN-ACK / ACK, then one IPv4-fragmented datagram per payload, then
    FIN-ACK."""
    pkts = []
    seq = rnd.randint(1000, 90000)
    ack = rnd.randint(1000, 90000)
    pkts.append(_set_ip_id(L.build_tcp_packet(src, dst, sport, dport, seq, 0, b"", 0x02), _ID.next()))
    seq += 1
    pkts.append(_set_ip_id(L.build_tcp_packet(dst, src, dport, sport, ack, seq, b"", 0x12), _ID.next()))
    ack += 1
    pkts.append(_set_ip_id(L.build_tcp_packet(src, dst, sport, dport, seq, ack, b"", 0x10), _ID.next()))
    for p in payloads:
        pkt = L.build_tcp_packet(src, dst, sport, dport, seq, ack, p, 0x18)
        pkts.extend(ip_fragmentize(pkt, rnd))
        seq += len(p)
    pkts.append(_set_ip_id(L.build_tcp_packet(src, dst, sport, dport, seq, ack, b"", 0x11), _ID.next()))
    return pkts


def main():
    out = L.out_dir("M02")
    rnd = random.Random(0x1A70C7)  # deterministic

    nonce = rnd.randint(0, 0xFFFFFFFF)      # per-session nonce

    real_frames = genuine_fragment_frames(rnd, nonce)
    fake_frames = naive_seal_frames(rnd, nonce)
    bad = bad_seal_frames(rnd, nonce)
    wrong_ot = wrong_outer_type_frames(rnd, nonce)
    wrong_in = wrong_inner_frames(rnd, nonce)

    # ---- TCP streams (airport tower theme) ---------------------------------
    streams = [
        ("10.20.30.2",  "10.20.30.10", 4001, 51000),  # tower uplink (flag)
        ("10.20.30.3",  "10.20.30.11", 4002, 51001),  # approach feed (decoys)
        ("10.20.30.7",  "10.20.30.2",  9000, 41000),  # radar sweep (mixed)
        ("10.20.30.20", "10.20.30.3",  8080, 52000),  # ground ops (noise)
        ("10.20.30.11", "10.20.30.2",  5001, 33000),  # baggage scanners
        ("10.20.30.10", "10.20.30.7",  9100, 60000),  # refuel telemetry
    ]

    # stream 0: the SESSION frame (nonce) MUST come first so an in-order walk
    # harvests the nonce before it can decode anything; the remaining genuine
    # fragments follow shuffled, plus one TCP payload carrying TWO frames
    # (must walk the payload frame by frame).
    s0_tail = [noise_line(rnd) for _ in range(9)]
    shuffled = list(real_frames[1:])
    rnd.shuffle(shuffled)               # out of order -> must sort by inner seq
    s0_tail += shuffled
    s0_tail.append(bad[0] + wrong_ot[0])
    rnd.shuffle(s0_tail)
    s0 = [real_frames[0]] + s0_tail     # keep the session frame first

    # stream 1: the naive-seal wrong-flag group (session frame first, rest
    # shuffled) + bad seals + noise
    s1_tail = [noise_line(rnd) for _ in range(10)]
    fake = list(fake_frames[1:])
    rnd.shuffle(fake)
    s1_tail += fake
    s1_tail += [bad[1] + bad[2], bad[3]]
    rnd.shuffle(s1_tail)
    s1 = [fake_frames[0]] + s1_tail

    # stream 2: wrong outer type + wrong inner type/magic + noise
    s2 = [noise_line(rnd) for _ in range(12)]
    s2 += [wrong_ot[1], wrong_ot[2], wrong_in[0], wrong_in[1], wrong_in[2]]
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
        "the ordinary network traffic, and those packets are wrapped again.\n"
        "Nobody has given us the wire format.\n"
        "\n"
        "Heads-up from the wire crew: the tower breaks its own datagrams apart\n"
        "in flight, so a lot of what looks like junk is really one message\n"
        "spread over several packets. Nothing reads right until you put the\n"
        "pieces of each datagram back together, in order, and only then walk\n"
        "the result top to bottom — the very first intact message hands you the\n"
        "session token you need to un-scramble everything that follows.\n"
        "\n"
        "Not everything on the wire is intact, and not everything that is\n"
        "intact is worth reading. The seal is not the obvious one — trust the\n"
        "tower's own rule, not the one you assume. Read only what the tower is\n"
        "actually broadcasting, in the order the tower sent it.\n"
        "\n"
        "Deliverable: the flight callsign (the recovered flag).\n"
    )
    (out / "MANIFEST.txt").write_text(manifest, encoding="utf-8")

    n_frames = (len(real_frames) + len(fake_frames) + len(bad)
                + len(wrong_ot) + len(wrong_in))
    print(f"[M02] wrote {len(packets)} packets -> {out/'airport_traffic.pcap'}")
    print(f"[M02] session nonce = {nonce:#010x}")
    print(f"[M02] genuine fragments = {len(real_frames)}  total frames = {n_frames}")
    print(f"[M02] decoys: naive_seal={len(fake_frames)} bad_seal={len(bad)} "
          f"wrong_outer_type={len(wrong_ot)} wrong_inner={len(wrong_in)}")
    print(f"[M02] flag = {FLAG}")


if __name__ == "__main__":
    main()
