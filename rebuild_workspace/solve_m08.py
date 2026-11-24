#!/usr/bin/env python3
"""M08 reference solver - Nightshift C2 (Part 3/3).

  1. Recover the live C2 endpoint + session id from Part 2 (solve_m07.recover()).
  2. Reassemble each TCP flow out of the capture and parse the NC2 frames.
  3. Only frames whose HMAC tag verifies under mac_key(session_id) survive:
     replays, tampered frames and the *other* flow's frames are dropped.
  4. The keystream is chained -- every frame mixes the previous *authenticated*
     frame's MAC -- so frames must be decrypted strictly in sequence order.
  5. ftype-0 diagnostic broadcasts are plaintext (a planted bait flag) and are
     ignored entirely.

``recover()`` returns the Part-3 flag.  Fully deterministic; reads only the
participant artifacts.
"""
import hashlib
import hmac
import struct
import sys
from pathlib import Path

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lib_fta as L
import solve_m07

MAGIC = b"NC2\x01"
M08_DIR = L.out_dir("M08")


def mac_key(sid: bytes) -> bytes:
    return hashlib.sha256(b"NS-C2-MAC" + sid).digest()


def frame_mac(sid: bytes, hv: bytes, ct: bytes) -> bytes:
    return hmac.new(mac_key(sid), hv + ct, hashlib.sha256).digest()[:16]


def keystream(prev: bytes, nonce: bytes, seq: int, n: int) -> bytes:
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(b"NS-C2-KS" + prev + nonce
                              + struct.pack("<I", seq) + struct.pack("<I", i)).digest()
        i += 1
    return bytes(out[:n])


def xor_key(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def iter_pcap_packets(raw: bytes):
    """Yield each packet's raw link-layer bytes from a classic pcap."""
    magic = struct.unpack("<I", raw[:4])[0]
    assert magic == 0xA1B2C3D4, "unsupported pcap magic %#x" % magic
    off, n = 24, len(raw)
    while off + 16 <= n:
        _ts, _tu, incl, _orig = struct.unpack("<IIII", raw[off:off + 16])
        off += 16
        yield raw[off:off + incl]
        off += incl


def _tcp_payload(pkt: bytes):
    """Return (src, dst, sport, dport, payload) for a raw IPv4/TCP packet."""
    if len(pkt) < 20 or (pkt[0] >> 4) != 4:
        return None
    ihl = (pkt[0] & 0x0F) * 4
    if pkt[9] != 6 or len(pkt) < ihl + 20:
        return None
    src = ".".join(str(b) for b in pkt[12:16])
    dst = ".".join(str(b) for b in pkt[16:20])
    t = pkt[ihl:]
    sport, dport = struct.unpack(">HH", t[:4])
    doff = (t[12] >> 4) * 4
    if doff < 20 or doff > len(t):
        return None
    return src, dst, sport, dport, t[doff:]


def flows(pcap_path: Path):
    """Yield (src, dst, sport, dport, concatenated-payload) per TCP 4-tuple."""
    raw = pcap_path.read_bytes()
    order, groups = [], {}
    for pkt in iter_pcap_packets(raw):
        got = _tcp_payload(pkt)
        if got is None:
            continue
        src, dst, sport, dport, payload = got
        if not payload:
            continue
        key = (src, dst, sport, dport)
        if key not in groups:
            groups[key] = bytearray()
            order.append(key)
        groups[key] += payload
    for key in order:
        yield key + (bytes(groups[key]),)


def parse_frames(blob: bytes):
    """Parse an NC2 frame stream into dicts."""
    out = []
    i, n = 0, len(blob)
    while i + 27 <= n:
        j = blob.find(MAGIC, i)
        if j < 0 or j + 27 > n:
            break
        ftype = blob[j + 4]
        seq = struct.unpack("<I", blob[j + 5:j + 9])[0]
        nonce = blob[j + 9:j + 25]
        ln = struct.unpack("<H", blob[j + 25:j + 27])[0]
        end = j + 27 + ln + 16
        if ln > 4096 or end > n:
            i = j + 1
            continue
        ct = blob[j + 27:j + 27 + ln]
        tag = blob[j + 27 + ln:end]
        out.append(dict(ftype=ftype, seq=seq, nonce=nonce, ct=ct, tag=tag,
                        hv=blob[j:j + 27]))
        i = end
    return out


def mac_ok(sid: bytes, fr: dict) -> bool:
    return hmac.compare_digest(frame_mac(sid, fr["hv"], fr["ct"]), fr["tag"])


def walk_chain(sid: bytes, frames):
    """MAC-gate, drop diagnostics, dedupe by seq, then decrypt in order."""
    valid = sorted((f for f in frames if f["ftype"] != 0x00 and mac_ok(sid, f)),
                   key=lambda f: f["seq"])
    prev = sid
    seen, pts = set(), []
    for fr in valid:
        if fr["seq"] in seen:
            continue
        seen.add(fr["seq"])
        ks = keystream(prev, fr["nonce"], fr["seq"], len(fr["ct"]))
        pts.append(xor_key(fr["ct"], ks))
        prev = fr["tag"]
    return pts


def recover(pcap_path: Path = None):
    """Recover the Part-3 flag from the live C2 flow."""
    _, _host, port, sid = solve_m07.recover()
    if pcap_path is None:
        pcap_path = M08_DIR / "nightshift_c2.pcap"
    pts = []
    for _src, _dst, _sport, dport, blob in flows(pcap_path):
        if dport != port:
            continue
        pts += walk_chain(sid, parse_frames(blob))
    joined = b"".join(pts)
    for line in joined.split(b"\n"):
        if b"FTA{" in line:
            k = line.index(b"FTA{")
            return line[k:line.index(b"}", k) + 1].decode("ascii")
    raise ValueError("no flag in the C2 exfil payload")


def solve():
    flag = recover()
    assert flag == L.FLAGS["M08"], "wrong flag: %r" % flag
    print("[M08] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
