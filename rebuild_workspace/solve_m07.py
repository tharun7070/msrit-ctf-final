#!/usr/bin/env python3
"""M07 reference solver - Nightshift Config (Part 2/3).

  1. Recover the dispatch token from Part 1 (via solve_m06.recover()).
  2. Parse the heap slice, validate every record's byte check, and XOR-combine
     the live ``KEY0``..``KEY3`` allocations (skipping the freed shadow K2SH and
     the unrelated live scratch TMP0) to rebuild the smeared key.
  3. Key the KDF with (token, ram_key) and authenticate the ``TAGV`` gate.
  4. Decrypt the ``LIVE`` section and read FLAG / C2 / SESSION out of it.
     The ``LEGC`` section only opens under the trap key and is bait.

``recover()`` returns ``(flag, host, port, session_id_bytes)`` for M08.
Fully deterministic; reads only the participant artifacts.
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
import solve_m06

MAGIC = b"NSCF"
M07_DIR = L.out_dir("M07")


def kdf(token: bytes, ram_key: bytes) -> bytes:
    return hashlib.sha256(b"NS-CFG-KEY" + token + ram_key).digest()


def mac(key: bytes, data: bytes) -> bytes:
    mk = hashlib.sha256(b"NS-CFG-MAC" + key).digest()
    return hmac.new(mk, data, hashlib.sha256).digest()[:16]


def keystream(key: bytes, n: int, iv: bytes) -> bytes:
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(key + iv + struct.pack("<I", i)).digest()
        i += 1
    return bytes(out[:n])


def xor_key(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_all(bufs):
    r = bytearray(len(bufs[0]))
    for b in bufs:
        for i in range(len(r)):
            r[i] ^= b[i]
    return bytes(r)


def parse_sections(buf: bytes):
    assert buf.startswith(MAGIC), "not a Nightshift config container"
    i = len(MAGIC) + 2
    sec = {}
    while i + 8 <= len(buf):
        tag = buf[i:i + 4]
        ln = struct.unpack("<I", buf[i + 4:i + 8])[0]
        i += 8
        sec[tag] = buf[i:i + ln]
        i += ln
    return sec


def dec_blob(key: bytes, blob: bytes) -> bytes:
    iv, ct, tag = blob[:8], blob[8:-16], blob[-16:]
    if mac(key, iv + ct) != tag:
        raise ValueError("config section failed its authentication tag")
    return xor_key(ct, keystream(key, len(ct), iv))


def parse_ram(buf: bytes):
    assert buf.startswith(b"NSRAM1"), "not a heap slice"
    n = struct.unpack("<H", buf[8:10])[0]
    i, recs = 10, []
    for _ in range(n):
        name, status = buf[i:i + 4], buf[i + 4]
        data, chk = buf[i + 5:i + 13], buf[i + 13]
        i += 16
        if (sum(data) ^ 0x5A) & 0xFF != chk:
            raise ValueError("heap record %r failed its check" % name)
        recs.append((name, status, data))
    return recs


def recover_ram_key(buf: bytes = None):
    if buf is None:
        buf = (M07_DIR / "ram_slice.bin").read_bytes()
    recs = parse_ram(buf)
    live = {name: data for name, status, data in recs if status == 1}
    bufs = [live[b"KEY%d" % i] for i in range(4)]
    return xor_all(bufs)


def _field(text: str, prefix: str) -> str:
    for line in text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):]
    raise KeyError(prefix)


def recover(cfg_buf: bytes = None, ram_buf: bytes = None):
    """Recover (flag, host, port, session_id_bytes)."""
    _, token = solve_m06.recover()
    ram_key = recover_ram_key(ram_buf)
    key = kdf(token, ram_key)

    if cfg_buf is None:
        cfg_buf = (M07_DIR / "nightshift_config.bin").read_bytes()
    sec = parse_sections(cfg_buf)
    if sec[b"TAGV"] != mac(token, b"ns-config-tag"):
        raise ValueError("dispatch token rejected by the config tag")
    text = dec_blob(key, sec[b"LIVE"]).decode("ascii")
    flag = _field(text, "FLAG:")
    host, port = _field(text, "C2:").rsplit(":", 1)
    sid = bytes.fromhex(_field(text, "SESSION:"))
    return flag, host, int(port), sid


def solve():
    flag, host, port, sid = recover()
    assert flag == L.FLAGS["M07"], "wrong flag: %r" % flag
    assert len(sid) == 16
    print("[M07] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
