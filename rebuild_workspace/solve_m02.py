#!/usr/bin/env python3
"""M02 — Airport Ghost Flight. Reference solver (private).

Inverts the nested, multi-layer protocol written by gen_m02.py:

  1. classic pcap -> IPv4 FRAGMENT REASSEMBLY (group by src/dst/id/proto, order
     by fragment offset) -> complete TCP segments -> TCP payloads (no scapy).
  2. SESSION nonce: the plaintext prefix SESSION_MAGIC|nonce rides on the FIRST
     genuine frame only; it must be harvested while walking the payloads in
     order, before any fragment can be unmasked.
  3. OUTER "tower seal frame" (little-endian):
         magic 0xDEAD1A70 | otype u16 | olen u16 | oseq u32
         | route u16 | payload(olen) | seal u32
     The seal covers frame[0:12] || payload; the 2-byte `route` field
     (frame[12:14]) is SKIPPED.  A naive whole-frame CRC32 fails on real frames.
  4. otype must be 0x0A.
  5. the NESTED inner "flight frame" inside the payload (different magic):
         magic 0x1A70C0DE | version u8 | itype u8 | iseq u32 | ilen u16
         | masked data
     version must be 1 and itype must be 0x5C.
  6. the inner data is unmasked with keystream(nonce, iseq) (an LCG keyed by the
     session nonce and the inner sequence number — NOT the frame CRC).
  7. fragments are ordered by the INNER iseq; the OUTER oseq is a red herring.

Accepted fragments are sorted by inner sequence and concatenated, then compared
against the real flag.
"""
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

OUTER_MAGIC = L.FRAME_MAGIC                     # 0xDEAD1A70
OUTER_MAGIC_BYTES = struct.pack("<I", OUTER_MAGIC)
INNER_MAGIC = 0x1A70C0DE
INNER_MAGIC_BYTES = struct.pack("<I", INNER_MAGIC)
SESSION_MAGIC = 0x5E5510A5
SESSION_MAGIC_BYTES = struct.pack("<I", SESSION_MAGIC)
OUTER_TYPE_DATA = 0x0A
INNER_VER = 1
INNER_TYPE_FRAG = 0x5C


def keystream(nonce: int, seq: int, n: int) -> bytes:
    state = ((seq * 0x9E3779B1) ^ nonce ^ 0xA5A5A5A5) & 0xFFFFFFFF
    out = bytearray(n)
    for i in range(n):
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        out[i] = (state >> 24) & 0xFF
    return bytes(out)


def apply_mask(data: bytes, nonce: int, seq: int) -> bytes:
    return bytes(a ^ b for a, b in zip(data, keystream(nonce, seq, len(data))))


def iter_pcap_packets(raw: bytes):
    """Yield each packet's raw link-layer bytes from a classic pcap."""
    magic = struct.unpack("<I", raw[:4])[0]
    assert magic == 0xA1B2C3D4, f"unsupported pcap magic {magic:#x}"
    off = 24  # global header
    n = len(raw)
    while off + 16 <= n:
        _ts, _tu, incl, _orig = struct.unpack("<IIII", raw[off:off + 16])
        off += 16
        yield raw[off:off + incl]
        off += incl


def reassemble_datagrams(packets):
    """Reassemble IPv4 fragments into full TCP segments (first-appearance
    order).  Unfragmented single-fragment datagrams pass through unchanged."""
    groups = {}
    order = []
    for pkt in packets:
        if len(pkt) < 20 or (pkt[0] >> 4) != 4:
            continue
        ihl = (pkt[0] & 0x0F) * 4
        if ihl < 20 or len(pkt) < ihl:
            continue
        proto = pkt[9]
        if proto != 6:                       # only TCP carries the frames
            continue
        total = (pkt[2] << 8) | pkt[3]
        ident = (pkt[4] << 8) | pkt[5]
        fo = (pkt[6] << 8) | pkt[7]
        off = (fo & 0x1FFF) * 8
        key = (bytes(pkt[12:16]), bytes(pkt[16:20]), ident, proto)
        seg = pkt[ihl:min(total, len(pkt))]
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append((off, seg))
    out = []
    for key in order:
        frags = sorted(groups[key], key=lambda t: t[0])
        out.append(b"".join(s for _o, s in frags))
    return out


def tcp_data(seg: bytes) -> bytes:
    """Return the TCP payload from a reassembled TCP segment."""
    if len(seg) < 20:
        return b""
    doff = (seg[12] >> 4) * 4
    if doff < 20 or doff > len(seg):
        return b""
    return seg[doff:]


def parse_outer_frames(payload: bytes):
    """Yield dicts for every OUTER frame found, with the genuine-seal verdict."""
    i = 0
    while True:
        j = payload.find(OUTER_MAGIC_BYTES, i)
        if j < 0 or j + 14 > len(payload):
            return
        otype, olen = struct.unpack("<HH", payload[j + 4:j + 8])
        end = j + 14 + olen
        if olen > 8192 or end + 4 > len(payload):
            i = j + 1
            continue
        oseq = struct.unpack("<I", payload[j + 8:j + 12])[0]
        route = struct.unpack("<H", payload[j + 12:j + 14])[0]
        pl = payload[j + 14:end]
        seal = struct.unpack("<I", payload[end:end + 4])[0]
        # genuine seal = crc32(header[0:12] || payload), route bytes skipped
        crc = zlib.crc32(payload[j:j + 12])
        crc = zlib.crc32(pl, crc)
        seal_ok = (crc & 0xFFFFFFFF) == seal
        # naive whole-frame CRC32 (over frame[0:14] || payload): the DECOY rule
        naive_ok = (zlib.crc32(payload[j:end]) & 0xFFFFFFFF) == seal
        yield dict(otype=otype, oseq=oseq, route=route, payload=pl,
                   seal=seal, seal_ok=seal_ok, naive_ok=naive_ok)
        i = end + 4


def parse_inner(pl: bytes):
    """Parse the NESTED inner frame; return (version, itype, iseq, masked) or None."""
    k = pl.find(INNER_MAGIC_BYTES)
    if k < 0 or k + 12 > len(pl):
        return None
    magic, ver, itype, iseq = struct.unpack("<IBBI", pl[k:k + 10])
    if magic != INNER_MAGIC:
        return None
    ilen = struct.unpack("<H", pl[k + 10:k + 12])[0]
    if k + 12 + ilen > len(pl):
        return None
    return ver, itype, iseq, pl[k + 12:k + 12 + ilen]


def session_nonce(pl: bytes):
    """Harvest the plaintext session nonce if this payload carries it."""
    if len(pl) >= 8 and pl[:4] == SESSION_MAGIC_BYTES:
        return struct.unpack("<I", pl[4:8])[0]
    return None


def extract_fragments(pcap_path: Path):
    """Return (frags, stats).

    frags: list of (inner_seq, decoded_bytes) for genuinely-valid fragments.
    stats: counts of ALL frames parsed vs payloads accepted.  `frames` counts
           every outer frame parsed (genuine + every decoy), so it is strictly
           greater than the number of accepted fragments; `packets` counts raw
           (fragmented) pcap records while `payloads` counts reassembled TCP
           segments, so packets > payloads whenever fragmentation is in play.
    """
    raw = pcap_path.read_bytes()
    packets = list(iter_pcap_packets(raw))
    segs = reassemble_datagrams(packets)

    n_frag_records = 0
    for pkt in packets:
        if len(pkt) >= 8 and (pkt[0] >> 4) == 4:
            fo = (pkt[6] << 8) | pkt[7]
            if fo & 0x3FFF:                  # MF set or fragment offset != 0
                n_frag_records += 1

    frags = []
    n_payloads = n_frames = 0
    nonce = None
    for seg in segs:
        payload = tcp_data(seg)
        if not payload:
            continue
        n_payloads += 1
        for fr in parse_outer_frames(payload):
            n_frames += 1
            if nonce is None:
                nonce = session_nonce(fr["payload"])
            if not fr["seal_ok"]:            # fails the genuine (subset) seal
                continue
            if fr["otype"] != OUTER_TYPE_DATA:
                continue
            inner = parse_inner(fr["payload"])
            if inner is None:
                continue
            ver, itype, iseq, masked = inner
            if ver != INNER_VER or itype != INNER_TYPE_FRAG:
                continue
            if nonce is None:
                continue
            frags.append((iseq, apply_mask(masked, nonce, iseq)))
    stats = dict(packets=len(packets), payloads=n_payloads, frames=n_frames,
                 fragments=n_frag_records)
    return frags, stats


def naive_reassembly(pcap_path: Path) -> str:
    """What a solver trusting the NAIVE whole-frame CRC32 would reconstruct.
    Used by the validator to prove the decoy trap fires (it must return the
    DECOY flag, never the real one)."""
    raw = pcap_path.read_bytes()
    segs = reassemble_datagrams(list(iter_pcap_packets(raw)))
    nonce = None
    acc = []
    for seg in segs:
        payload = tcp_data(seg)
        if not payload:
            continue
        for fr in parse_outer_frames(payload):
            if nonce is None:
                nonce = session_nonce(fr["payload"])
            if not fr["naive_ok"]:
                continue
            if fr["otype"] != OUTER_TYPE_DATA:
                continue
            inner = parse_inner(fr["payload"])
            if inner is None:
                continue
            ver, itype, iseq, masked = inner
            if ver != INNER_VER or itype != INNER_TYPE_FRAG:
                continue
            if nonce is None:
                continue
            acc.append((iseq, apply_mask(masked, nonce, iseq)))
    acc.sort(key=lambda t: t[0])
    return "".join(d.decode("ascii", "replace") for _s, d in acc)


def solve():
    pcap = L.out_dir("M02") / "airport_traffic.pcap"
    frags, stats = extract_fragments(pcap)
    frags.sort(key=lambda t: t[0])
    flag = "".join(d.decode("ascii") for _s, d in frags)
    assert flag == L.FLAGS["M02"], f"decoded {flag!r} != expected"
    print(f"[M02] PASS -> {flag}")
    return flag


if __name__ == "__main__":
    solve()
