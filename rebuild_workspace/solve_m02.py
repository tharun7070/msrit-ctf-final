#!/usr/bin/env python3
"""M02 — Airport Ghost Flight. Reference solver (private).

Parses `airport_traffic.pcap` by hand (no scapy): walks the classic pcap record
headers, decodes IPv4/TCP, then scans every TCP payload for the custom frame
MAGIC 0xDEAD1A70.  Frames are parsed as:

    MAGIC(u32 LE) | type(u16 LE) | length(u16 LE) | payload | CRC32(u32 LE)

A frame is accepted only when its CRC32 (zlib.crc32 over MAGIC|type|length|payload)
matches the stored value AND type == 0x0A.  Accepted payloads are laid out as:

    payload[0:6]   opaque header
    payload[6:10]  sequence (u32 LE)
    payload[10:]   data XOR (frame's 4 CRC32 bytes, repeated)

Fragments are sorted by sequence, XOR-decoded, concatenated, and compared to the
real flag.
"""
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

MAGIC = L.FRAME_MAGIC
MAGIC_BYTES = struct.pack("<I", MAGIC)
TYPE_DATA = 0x0A


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
    src = ".".join(str(b) for b in pkt[12:16])
    dst = ".".join(str(b) for b in pkt[16:20])
    tcp = pkt[ihl:]
    doff = (tcp[12] >> 4) * 4
    if doff < 20:
        return None
    end = min(ip_total, len(pkt))
    payload = pkt[ihl + doff:end]
    return src, dst, payload


def parse_frames(payload: bytes):
    """Yield (type, frame_payload, crc_ok) for every frame found in `payload`."""
    i = 0
    while True:
        j = payload.find(MAGIC_BYTES, i)
        if j < 0 or j + 8 > len(payload):
            return
        ftype, flen = struct.unpack("<HH", payload[j + 4:j + 8])
        end = j + 8 + flen
        if flen > 4096 or end + 4 > len(payload):
            i = j + 1
            continue
        body = payload[j:end]
        stored_crc = struct.unpack("<I", payload[end:end + 4])[0]
        ok = (zlib.crc32(body) & 0xFFFFFFFF) == stored_crc
        yield ftype, payload[j + 8:end], stored_crc, ok
        i = end + 4  # step past this frame


def decode_frame(pl: bytes, crc: int) -> bytes:
    """payload[6:10]=seq(LE), payload[10:]=data XOR crc bytes (LE, repeated)."""
    cb = (crc & 0xFFFFFFFF).to_bytes(4, "little")
    enc = pl[10:]
    return bytes(b ^ cb[k % 4] for k, b in enumerate(enc))


def extract_fragments(pcap_path: Path):
    raw = pcap_path.read_bytes()
    frags = []
    n_pkts = n_payloads = n_frames = 0
    for pkt in iter_pcap_packets(raw):
        n_pkts += 1
        tp = tcp_payload(pkt)
        if not tp:
            continue
        _src, _dst, payload = tp
        if not payload:
            continue
        n_payloads += 1
        for ftype, fpl, crc, ok in parse_frames(payload):
            n_frames += 1
            if not ok or ftype != TYPE_DATA:
                continue
            if len(fpl) < 10:
                continue
            seq = struct.unpack("<I", fpl[6:10])[0]
            frags.append((seq, decode_frame(fpl, crc)))
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
