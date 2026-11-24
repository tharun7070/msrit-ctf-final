#!/usr/bin/env python3
"""E08 reference solver.

Inverts the Dead Drop Uplink capture:
  1. parse the classic little-endian pcap into raw frames;
  2. walk Ethernet+IPv4+UDP to the custom payload header;
  3. keep the genuine protocol family (MAGIC 0xE1D0); find the CONTROL key
     packet and bind its SESSION to the DATA fragments of that session;
  4. CRC-validate each fragment, order by SEQ, decode the session key from
     base64(rot13(hex(SK))), XOR the SHA256 keystream and zlib-inflate.

The decoy family (MAGIC 0xD1E0) is deliberately ignored here; the validator
inspects it separately to prove it never yields the real flag.
"""
import base64
import hashlib
import re
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

MAGIC_GENUINE = 0xE1D0
MAGIC_DECOY = 0xD1E0
PORT_CONTROL = 4444
PORT_DATA_GENUINE = 4445
PORT_DATA_DECOY = 4446


# ---------------------------------------------------------------------------
# codec helpers
# ---------------------------------------------------------------------------
def crc16_ccitt_false(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def rot13(text: str) -> str:
    out = []
    for ch in text:
        if "a" <= ch <= "z":
            out.append(chr((ord(ch) - 97 + 13) % 26 + 97))
        elif "A" <= ch <= "Z":
            out.append(chr((ord(ch) - 65 + 13) % 26 + 65))
        else:
            out.append(ch)
    return "".join(out)


def key_from_fragment(frag: bytes) -> bytes:
    """sk = bytes.fromhex( rot13( ascii( base64decode(frag) ) ) )"""
    txt = base64.b64decode(frag).decode("ascii")
    return bytes.fromhex(rot13(txt))


def encode_key_fragment(sk: bytes) -> bytes:
    return base64.b64encode(rot13(sk.hex()).encode("ascii"))


def keystream(key: bytes, n: int) -> bytes:
    base = hashlib.sha256(key).digest()
    return (base * ((n + len(base) - 1) // len(base)))[:n]


# ---------------------------------------------------------------------------
# pcap / packet parsing
# ---------------------------------------------------------------------------
def parse_pcap(raw: bytes):
    """Classic little-endian pcap -> list of raw frame byte strings."""
    magic, vmaj, vmin, _tz, _sf, _snap, _link = struct.unpack_from("<IHHiIII", raw, 0)
    assert magic == 0xA1B2C3D4, "not a classic little-endian pcap"
    off = 24
    frames = []
    while off + 16 <= len(raw):
        _ts, _tu, incl, _orig = struct.unpack_from("<IIII", raw, off)
        off += 16
        frames.append(raw[off:off + incl])
        off += incl
    return frames


def udp_payload(eth: bytes):
    """Ethernet/IPv4/UDP -> (sport, dport, payload)."""
    assert eth[12:14] == b"\x08\x00", "not IPv4"
    ip = eth[14:]
    assert (ip[0] >> 4) == 4
    ihl = (ip[0] & 0x0F) * 4
    assert ip[9] == 17, "not UDP"
    udp = ip[ihl:]
    sport, dport, ulen, _csum = struct.unpack("!HHHH", udp[:8])
    return sport, dport, udp[8:8 + (ulen - 8)]


def parse_header(payload: bytes):
    """MAGIC + SESSION + SEQ + CRC16 + FRAGMENT."""
    magic, session, seq, crc = struct.unpack("!HHHH", payload[:8])
    return magic, session, seq, crc, payload[8:]


def collect(frames, magic):
    """Group frames of one magic into {session: {'ctrl': frag, 'frags': {seq: frag}}}.

    DATA fragments that fail CRC16 are dropped."""
    sessions = {}
    for eth in frames:
        if eth[12:14] != b"\x08\x00":
            continue
        _sport, dport, payload = udp_payload(eth)
        if len(payload) < 8:
            continue
        m, session, seq, crc, frag = parse_header(payload)
        if m != magic:
            continue
        ent = sessions.setdefault(session, {"ctrl": None, "frags": {}})
        if dport == PORT_CONTROL:
            ent["ctrl"] = frag
        elif crc16_ccitt_false(frag) == crc:
            ent["frags"][seq] = frag
    return sessions


def decode_session(control_frag: bytes, seq_frags: dict) -> str:
    """Rebuild the parcel for one session (may raise on a bad key/CRC)."""
    key = key_from_fragment(control_frag)
    ciphertext = b"".join(seq_frags[i] for i in sorted(seq_frags))
    ks = keystream(key, len(ciphertext))
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, ks))
    return zlib.decompress(plaintext).decode("ascii")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def solve():
    raw = (L.out_dir("E08") / "dead_drop.pcap").read_bytes()
    frames = parse_pcap(raw)

    genuine = collect(frames, MAGIC_GENUINE)
    flag = None
    for session, ent in sorted(genuine.items()):
        if ent["ctrl"] is None:
            continue
        try:
            text = decode_session(ent["ctrl"], ent["frags"])
        except (zlib.error, ValueError):
            continue
        m = re.search(r"FTA\{[a-z0-9_]+\}", text)
        if m:
            flag = m.group(0)
            break

    assert flag == L.FLAGS["E08"], ("unexpected flag", flag)
    print("[E08] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
