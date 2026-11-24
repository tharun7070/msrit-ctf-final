#!/usr/bin/env python3
"""M02 — Airport Ghost Flight. Reference solver (private).

Inverts the nested, multi-layer protocol written by gen_m02.py:

  1. classic pcap -> IPv4/TCP -> TCP payloads (no scapy).
  2. OUTER "tower seal frame" (little-endian):
         magic 0xDEAD1A70 | otype u16 | olen u16 | oseq u32
         | route u16 | payload(olen) | seal u32
     The seal covers frame[0:12] || payload; the 2-byte `route` field
     (frame[12:14]) is SKIPPED.  A naive whole-frame CRC32 fails on real frames.
  3. otype must be 0x0A.
  4. the NESTED inner "flight frame" inside the payload (different magic):
         magic 0x1A70C0DE | version u8 | itype u8 | iseq u32 | ilen u16
         | masked data
     version must be 1 and itype must be 0x5C.
  5. the inner data is unmasked with keystream(iseq) (an LCG keyed by the
     inner sequence number — NOT the frame CRC).
  6. fragments are ordered by the INNER iseq; the OUTER oseq is a red herring.

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
OUTER_TYPE_DATA = 0x0A
INNER_VER = 1
INNER_TYPE_FRAG = 0x5C


def keystream(seq: int, n: int) -> bytes:
    state = (seq ^ 0xA5A5A5A5) & 0xFFFFFFFF
    out = bytearray(n)
    for i in range(n):
        state = (state * 1664525 + 1013904223) & 0xFFFFFFFF
        out[i] = (state >> 24) & 0xFF
    return bytes(out)


def apply_mask(data: bytes, seq: int) -> bytes:
    return bytes(a ^ b for a, b in zip(data, keystream(seq, len(data))))


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


def tcp_payload(pkt: bytes):
    """Extract the TCP payload from a raw Ethernet-less IPv4/TCP packet."""
    if len(pkt) < 20:
        return None
    version = pkt[0] >> 4
    ihl = (pkt[0] & 0x0F) * 4
    if version != 4 or ihl < 20 or len(pkt) < ihl + 20:
        return None
    if pkt[9] != 6:  # not TCP
        return None
    ip_total = (pkt[2] << 8) | pkt[3]
    tcp = pkt[ihl:]
    doff = (tcp[12] >> 4) * 4
    if doff < 20:
        return None
    end = min(ip_total, len(pkt))
    return pkt[ihl + doff:end]


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
        yield dict(otype=otype, oseq=oseq, route=route, payload=pl,
                   seal=seal, seal_ok=seal_ok)
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


def extract_fragments(pcap_path: Path):
    """Return (frags, stats).

    frags: list of (inner_seq, decoded_bytes) for genuinely-valid fragments.
    stats: counts of ALL frames parsed vs payloads accepted.  `frames` counts
           every outer frame parsed (genuine + every decoy), so it is strictly
           greater than the number of accepted fragments.
    """
    raw = pcap_path.read_bytes()
    frags = []
    n_pkts = n_payloads = n_frames = 0
    for pkt in iter_pcap_packets(raw):
        n_pkts += 1
        payload = tcp_payload(pkt)
        if not payload:
            continue
        n_payloads += 1
        for fr in parse_outer_frames(payload):
            n_frames += 1
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
            frags.append((iseq, apply_mask(masked, iseq)))
    return frags, dict(packets=n_pkts, payloads=n_payloads, frames=n_frames)


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
