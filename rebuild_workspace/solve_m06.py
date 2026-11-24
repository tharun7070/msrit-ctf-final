#!/usr/bin/env python3
"""M06 reference solver - Nightshift Loader (Part 1/3).

Reverses the crew's private container:

  1. Walk the section table (magic ``NSLF``, then key/len sections).
  2. Un-rotate ``KEYT`` by the header's ``rort`` byte -- the note's "used as
     stored" route is a plant and fails the body's CRC gate.
  3. XOR the ``PACK`` body against the SHA-256 counter keystream of that key.
  4. Confirm zlib.crc32(decoded text) == the stored crc, then custom base-40
     decode the text using the alphabet in ``CHST``.
  5. Parse ``FLAG:`` and ``TOKEN:`` out of the payload.  The token is exported
     for Part 2.

``recover()`` returns ``(flag, token_bytes)`` and is reused by solve_m07.py.
Fully deterministic; reads only the participant artifacts.
"""
import hashlib
import struct
import sys
import zlib
from pathlib import Path

sys.dont_write_bytecode = True

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lib_fta as L

MAGIC = b"NSLF"
ALPHABET = "z0q1m2p3v4x5k6b7n8w9_t!r@d#gcfhyjlasoeiu"
BASE = len(ALPHABET)
M06_DIR = L.out_dir("M06")


def rotate_tab(key: bytes, r: int) -> bytes:
    r %= len(key)
    return key[r:] + key[:r]


def keystream(key: bytes, n: int) -> bytes:
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(key + struct.pack("<I", i)).digest()
        i += 1
    return bytes(out[:n])


def xor_key(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def b40_decode(s: str) -> bytes:
    v = 0
    for ch in s:
        v = v * BASE + ALPHABET.index(ch)
    return v.to_bytes((v.bit_length() + 7) // 8, "big")


def parse_container(buf: bytes):
    """Return (rort, {tag: data})."""
    assert buf.startswith(MAGIC), "not a Nightshift loader container"
    rort = buf[6]
    i = len(MAGIC) + 3
    sec = {}
    while i + 8 <= len(buf):
        tag = buf[i:i + 4]
        ln = struct.unpack("<I", buf[i + 4:i + 8])[0]
        i += 8
        sec[tag] = buf[i:i + ln]
        i += ln
    return rort, sec


def decode_payload(sec: dict, rort: int) -> bytes:
    key = rotate_tab(sec[b"KEYT"], -rort)          # un-rotate the key table
    pack = sec[b"PACK"]
    crc = struct.unpack("<I", pack[:4])[0]
    enc = xor_key(pack[4:], keystream(key, len(pack) - 4))
    if zlib.crc32(enc) & 0xFFFFFFFF != crc:
        raise ValueError("PACK body failed its checksum (wrong key or rotation)")
    text = enc.decode("ascii")
    return b40_decode(text)


def _field(payload: bytes, name: bytes) -> bytes:
    for line in payload.split(b"\n"):
        if line.startswith(name):
            return line[len(name):]
    raise KeyError(name)


def recover(buf: bytes = None):
    """Recover (flag_str, token_bytes) from the shipped container."""
    if buf is None:
        buf = (M06_DIR / "nightshift_loader.bin").read_bytes()
    rort, sec = parse_container(buf)
    payload = decode_payload(sec, rort)
    flag = _field(payload, b"FLAG:").decode("ascii")
    token = bytes.fromhex(_field(payload, b"TOKEN:").decode("ascii"))
    return flag, token


def solve():
    flag, token = recover()
    assert flag == L.FLAGS["M06"], "wrong flag: %r" % flag
    assert len(token) == 16, "dispatch token must be 16 bytes"
    print("[M06] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
