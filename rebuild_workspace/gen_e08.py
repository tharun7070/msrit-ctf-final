#!/usr/bin/env python3
"""E08 - Dead Drop Uplink (custom UDP protocol over a classic pcap).

Produces `dead_drop.pcap` (raw Ethernet/IPv4/UDP frames) plus a
participant-facing `UPLINK_SPEC.txt`. The capture carries TWO sessions that
share the same payload framing and differ by their 2-byte SESSION id:

  genuine : MAGIC=0xE1D0, SESSION=0x1001, CONTROL on UDP/4444, DATA on UDP/4445.
  decoy   : MAGIC=0xD1E0, SESSION=0x2002, CONTROL on UDP/4444, DATA on UDP/4446.

The custom payload header is:
    MAGIC(2 BE) + SESSION(2 BE) + SEQ(2 BE) + CRC16(2 BE) + FRAGMENT
CRC16 is CRC-16/CCITT-FALSE over the FRAGMENT bytes.

Chain (generation):
  1. S = canonical flag string.
  2. P = zlib.compress(S); split into N fragments of 16 bytes.
  3. SK = fixed 16-byte key. keystream = SHA256(SK) repeated; each fragment is
     XORed with the keystream at its global byte offset.
  4. CONTROL packet carries base64(rot13(hex(SK))); N DATA packets carry the
     XORed fragments with correct CRC16.
  5. A decoy session (different magic/session/port) reassembles to a DECOY flag.

TRAP: UPLINK_SPEC.txt documents the header with MAGIC 0xE1D0 but advertises the
legacy data port 4446 and the replayed-frame magic 0xD1E0, so a naive triage
filter lands on the decoy session. The REAL flag never appears verbatim in any
artifact. Deterministic output. Private organizer tooling.
"""
import base64
import hashlib
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

# --- protocol constants -----------------------------------------------------
MAGIC_GENUINE = 0xE1D0
MAGIC_DECOY = 0xD1E0            # the "legacy/replay" magic advertised in the spec
PORT_CONTROL = 4444
PORT_DATA_GENUINE = 4445
PORT_DATA_DECOY = 4446          # "legacy" data port advertised in the spec (TRAP)
SESSION_GENUINE = 0x1001
SESSION_DECOY = 0x2002

FRAG = 16                       # fragment size in bytes

# fixed 16-byte keys (deterministic, never shipped to participants)
SK = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
DECOY_KEY = bytes.fromhex("c0ffee0011badc0de5ca1ab1ef00dbee")

DECOY_FLAG = "FTA{r3pl4y3d_s3ss10n_b41t}"

# --- link addressing --------------------------------------------------------
SRC_MAC = bytes.fromhex("02aa02000005")
DST_MAC = bytes.fromhex("02bb03000009")
SRC_IP = "10.13.37.5"
DST_IP = "10.13.37.9"
SRC_PORT_BASE = 40000


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def crc16_ccitt_false(data: bytes) -> int:
    """CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflect, xorout 0."""
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


def key_fragment(sk: bytes) -> bytes:
    """base64(rot13(hex(SK))) as it travels in a CONTROL fragment."""
    return base64.b64encode(rot13(sk.hex()).encode("ascii"))


def _csum(data: bytes) -> int:
    if len(data) & 1:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_udp_packet(sport: int, dport: int, payload: bytes) -> bytes:
    """Raw Ethernet + IPv4 + UDP frame carrying `payload`."""
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    pseudo = (
        bytes(int(x) for x in SRC_IP.split("."))
        + bytes(int(x) for x in DST_IP.split("."))
        + struct.pack("!BBH", 0, 17, 8 + len(payload))
    )
    ucsum = _csum(pseudo + udp + payload) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", ucsum)

    total = 20 + len(udp) + len(payload)
    ip = struct.pack("!BBHHHBBH", 0x45, 0, total, 0x4242, 0x4000, 64, 17, 0)
    ip += bytes(int(x) for x in SRC_IP.split("."))
    ip += bytes(int(x) for x in DST_IP.split("."))
    ip = ip[:10] + struct.pack("!H", _csum(ip)) + ip[12:]

    eth = DST_MAC + SRC_MAC + struct.pack("!H", 0x0800)
    return eth + ip + udp + payload


def frame(magic: int, session: int, seq: int, fragment: bytes) -> bytes:
    crc = crc16_ccitt_false(fragment)
    return struct.pack("!HHHH", magic, session, seq, crc) + fragment


def keystream(key: bytes, n: int) -> bytes:
    base = hashlib.sha256(key).digest()
    return (base * ((n + len(base) - 1) // len(base)))[:n]


def xor_stream(data: bytes, key: bytes) -> bytes:
    ks = keystream(key, len(data))
    return bytes(d ^ k for d, k in zip(data, ks))


def build_session(session, magic, control_port, data_port, flag, key):
    """Return the list of raw frames for one drop session."""
    plaintext = zlib.compress(flag.encode())
    ciphertext = xor_stream(plaintext, key)
    frags = [ciphertext[i:i + FRAG] for i in range(0, len(ciphertext), FRAG)]

    pkts = [build_udp_packet(SRC_PORT_BASE, control_port,
                             frame(magic, session, 0, key_fragment(key)))]
    for i, f in enumerate(frags):
        pkts.append(build_udp_packet(SRC_PORT_BASE + 1 + i, data_port,
                                     frame(magic, session, i, f)))
    return pkts


SPEC = """\
DEAD DROP UPLINK - FIELD NOTES (recovered from a burner handset)
================================================================

The crew never talks. They drop small parcels onto an unlisted UDP uplink,
one UDP datagram per fragment, no handshake. Capture the feed, rebuild the
parcel, inflate it.

FRAME (custom payload; begins immediately after the 8-byte UDP header)
---------------------------------------------------------------------
  MAGIC     2 bytes   big-endian   0xE1D0
  SESSION   2 bytes   big-endian   drop session id
  SEQ       2 bytes   big-endian   fragment index inside the session
  CRC16     2 bytes   big-endian   CRC-16/CCITT-FALSE over FRAGMENT
  FRAGMENT  (rest)                 opaque fragment bytes

  CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, no reflection, xor-out
  0x0000. Drop any fragment that fails the check.

PORTS
  CONTROL   4444   exactly one packet per session; its FRAGMENT is the key
  DATA      4446   the legacy uplink data port the drop still uses

KEY DELIVERY (CONTROL.fragment)
  base64( rot13( hex(SK) ) )  ->  16-byte session key SK

PARCEL REASSEMBLY
  Sort the session's DATA fragments by SEQ, concatenate, XOR the whole
  buffer with the keystream = SHA256(SK) repeated, then zlib-inflate. The
  result is the drop payload (a single ASCII line).

REPLAYS / LEGACY
  Timed-out batches are replayed verbatim. A replayed parcel is framed with
  MAGIC 0xD1E0 and left on the legacy data port; a lazy filter such as
  udp.port == 4446  or  magic == 0xD1E0  will latch onto the REPLAY first.
  One such replayed parcel inflates to:

        FTA{r3pl4y3d_s3ss10n_b41t}        <- DECOY, do not submit

  The live drop re-keyed its magic; trust the CRC, not these notes.
"""


def main():
    out = L.out_dir("E08")
    flag = L.FLAGS["E08"]

    genuine = build_session(SESSION_GENUINE, MAGIC_GENUINE, PORT_CONTROL,
                            PORT_DATA_GENUINE, flag, SK)
    decoy = build_session(SESSION_DECOY, MAGIC_DECOY, PORT_CONTROL,
                          PORT_DATA_DECOY, DECOY_FLAG, DECOY_KEY)

    # deterministic round-robin interleave (genuine first)
    packets = []
    for i in range(max(len(genuine), len(decoy))):
        if i < len(genuine):
            packets.append(genuine[i])
        if i < len(decoy):
            packets.append(decoy[i])

    pcap_path = out / "dead_drop.pcap"
    L.write_pcap(pcap_path, packets)
    L.write_text("E08", "UPLINK_SPEC.txt", SPEC)

    # ---------------------------------------------------------------- verify
    blob = pcap_path.read_bytes()
    assert flag.encode() not in blob, "REAL flag leaked into the pcap!"
    assert flag.encode() not in SPEC.encode(), "REAL flag leaked into the spec!"
    assert DECOY_FLAG.encode() in SPEC.encode(), "decoy flag missing from spec"
    assert crc16_ccitt_false(b"123456789") == 0x29B1, "CRC-16/CCITT-FALSE bad"

    # round-trip the genuine session end to end
    plaintext = zlib.compress(flag.encode())
    ciphertext = xor_stream(plaintext, SK)
    assert xor_stream(ciphertext, SK) == plaintext
    assert zlib.decompress(plaintext).decode() == flag

    print("wrote %s (%d frames)" % (pcap_path, len(packets)))
    print("wrote %s" % (out / "UPLINK_SPEC.txt"))
    print("[E08] genuine session=0x%04X magic=0x%04X data=udp/%d | "
          "decoy session=0x%04X magic=0x%04X data=udp/%d"
          % (SESSION_GENUINE, MAGIC_GENUINE, PORT_DATA_GENUINE,
             SESSION_DECOY, MAGIC_DECOY, PORT_DATA_DECOY))


if __name__ == "__main__":
    main()
