#!/usr/bin/env python3
"""COURIER RELAY PROTOCOL (CRP) - shared codec for the E11/E12 relay pair.

The crew never speaks. Small parcels are dropped onto an unlisted UDP relay,
one datagram per fragment, no handshake. Every frame begins immediately after
the 8-byte UDP header with the custom header:

    MAGIC(2 BE) + SESSION(2 BE) + SEQ(2 BE) + CRC16(2 BE) + FRAGMENT

  * CRC16 is CRC-16/CCITT-FALSE over FRAGMENT bytes.
  * CONTROL frame  : SEQ = 0xFFFF, FRAGMENT = base64(rot13(hex(SK))).
  * DATA frames    : SEQ = fragment index, FRAGMENT = ciphertext fragment.

The parcel is zlib(flag) XORed with the SHA256(SK) keystream. Fragments may be
delivered on two data sub-streams (even/odd SEQ) that a solver must merge.

E11 ("Ghost Relay") is a static wire capture of one relay burst; E12 ("Relay
Archive") is the same protocol captured offline later. Both are offline
artifacts. Private organizer tooling - never shipped verbatim to participants.
"""
import base64
import hashlib
import struct
import zlib

# --- framing / ports --------------------------------------------------------
FRAME_MAGIC_GENUINE = 0xCB01
FRAME_MAGIC_DECOY = 0xCB02     # legacy/replay magic advertised in the trap spec
BEACON_MAGIC = 0xCBFF          # client -> relay probe prefix

PORT_BEACON = 7000             # relay listens here; CONTROL replies leave here
PORT_DATA_A = 7001             # data sub-stream A (even fragment index)
PORT_DATA_B = 7002             # data sub-stream B (odd fragment index)
PORT_DECOY = 7003              # legacy replay port (trap)

SESSION_E11 = 0xC11A           # the Ghost Relay capture's session tag (E12 reuses it)
SESSION_DECOY = 0xC0DE

SEQ_CONTROL = 0xFFFF
FRAG = 16

# --- fixed 16-byte keys (deterministic; never shipped to participants) -------
SK_E11 = bytes.fromhex("1a2b3c4d5e6f708192a3b4c5d6e7f809")
SK_E12 = bytes.fromhex("f0e1d2c3b4a5968778695a4b3c2d1e0f")
DECOY_KEY = bytes.fromhex("c0ffee0011badc0de5ca1ab1ef00dbee")


# ---------------------------------------------------------------------------
# primitives
# ---------------------------------------------------------------------------
def crc16_ccitt_false(data: bytes) -> int:
    """CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflect, xorout 0."""
    crc = 0xFFFF
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
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


def key_fragment(sk: bytes) -> bytes:
    return base64.b64encode(rot13(sk.hex()).encode("ascii"))


def key_from_fragment(frag: bytes) -> bytes:
    return bytes.fromhex(rot13(base64.b64decode(frag).decode("ascii")))


def keystream(key: bytes, n: int) -> bytes:
    base = hashlib.sha256(key).digest()
    return (base * ((n + len(base) - 1) // len(base)))[:n]


def xor_stream(data: bytes, key: bytes) -> bytes:
    return bytes(d ^ k for d, k in zip(data, keystream(key, len(data))))


# ---------------------------------------------------------------------------
# frame codec
# ---------------------------------------------------------------------------
def frame(magic: int, session: int, seq: int, fragment: bytes) -> bytes:
    return struct.pack("!HHHH", magic, session, seq, crc16_ccitt_false(fragment)) + fragment


def parse_frame(payload: bytes):
    """-> (magic, session, seq, crc16, fragment)."""
    if len(payload) < 8:
        raise ValueError("short frame")
    magic, session, seq, crc = struct.unpack("!HHHH", payload[:8])
    return magic, session, seq, crc, payload[8:]


# ---------------------------------------------------------------------------
# parcel builder
# ---------------------------------------------------------------------------
def build_control(session: int, magic: int, sk: bytes) -> bytes:
    return frame(magic, session, SEQ_CONTROL, key_fragment(sk))


def build_data_frames(flag: str, session: int, magic: int, sk: bytes,
                      two_streams: bool = False):
    """Return a list of (sub_stream_index, raw_frame) for one drop.

    sub_stream_index is 0 (A) or 1 (B) when two_streams is set, else always 0.
    The solver merges A/B back into global SEQ order.
    """
    ciphertext = xor_stream(zlib.compress(flag.encode()), sk)
    frags = [ciphertext[i:i + FRAG] for i in range(0, len(ciphertext), FRAG)]
    out = []
    for i, f in enumerate(frags):
        lane = (i & 1) if two_streams else 0
        out.append((lane, frame(magic, session, i, f)))
    return out


# ---------------------------------------------------------------------------
# raw Ethernet/IPv4/UDP (for pcap generation)
# ---------------------------------------------------------------------------
def _ip_checksum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_udp(src_mac, dst_mac, src_ip, dst_ip, sport, dport, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    pseudo = (bytes(int(x) for x in src_ip.split("."))
              + bytes(int(x) for x in dst_ip.split("."))
              + struct.pack("!BBH", 0, 17, 8 + len(payload)))
    ucsum = _ip_checksum(pseudo + udp + payload) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", ucsum)

    total = 20 + len(udp) + len(payload)
    ip = struct.pack("!BBHHHBBH", 0x45, 0, total, 0x7A11, 0x4000, 64, 17, 0)
    ip += bytes(int(x) for x in src_ip.split(".")) + bytes(int(x) for x in dst_ip.split("."))
    ip = ip[:10] + struct.pack("!H", _ip_checksum(ip)) + ip[12:]
    return dst_mac + src_mac + struct.pack("!H", 0x0800) + ip + udp + payload


def write_pcap(path, packets):
    out = bytearray()
    out += struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    ts = 1_700_000_000
    for i, pkt in enumerate(packets):
        out += struct.pack("<IIII", ts + i, i * 1000, len(pkt), len(pkt))
        out += pkt
    path.write_bytes(bytes(out))


def parse_pcap(raw: bytes):
    """Classic little-endian pcap -> list of raw Ethernet frames."""
    magic = struct.unpack_from("<I", raw, 0)[0]
    assert magic == 0xA1B2C3D4, "not a classic little-endian pcap"
    frames, off = [], 24
    while off + 16 <= len(raw):
        _a, _b, incl, _c = struct.unpack_from("<IIII", raw, off)
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
    sport, dport, ulen, _csum = struct.unpack("!HHHH", ip[ihl:ihl + 8])
    return sport, dport, ip[ihl + 8:ihl + 8 + (ulen - 8)]


# ---------------------------------------------------------------------------
# drop reassembly (used by solvers and the black-box validator)
# ---------------------------------------------------------------------------
def decode_drop(control_frag: bytes, seq_frags: dict) -> str:
    """Rebuild a parcel from its CONTROL fragment and {seq: fragment} map."""
    key = key_from_fragment(control_frag)
    ciphertext = b"".join(seq_frags[i] for i in sorted(seq_frags))
    return zlib.decompress(xor_stream(ciphertext, key)).decode("ascii")


if __name__ == "__main__":
    assert crc16_ccitt_false(b"123456789") == 0x29B1
    sk = SK_E11
    f = frame(FRAME_MAGIC_GENUINE, SESSION_E11, 0, b"abc")
    assert parse_frame(f)[:4] == (FRAME_MAGIC_GENUINE, SESSION_E11, 0, crc16_ccitt_false(b"abc"))
    assert key_from_fragment(key_fragment(sk)) == sk
    assert xor_stream(xor_stream(b"parcel", sk), sk) == b"parcel"
    print("relay_proto self-test OK")
