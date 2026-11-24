#!/usr/bin/env python3
"""M07 - Nightshift Config (Part 2 of 3): RAM-smeared key + token-keyed config.

Ships an encrypted configuration container (``NSCF``) plus a raw "heap slice"
(``ram_slice.bin``) and a recovery note that pushes the wrong route.

The configuration is keyed with Part 1's dispatch token combined with a key
that is *smeared* across the heap allocations (the live ``KEY0``..``KEY3``
buffers XOR-combined).  The slice also keeps a retired shadow of one buffer
(``K2SH``, differing in a single nibble) and an unrelated live scratch buffer
(``TMP0``); both are traps.  Following the note (shadow buffer + the sealed
*legacy* section) decrypts a decoy config that carries a bait flag.

The live config yields the Part-2 flag plus the C2 endpoint and session id that
Part 3 (M08) demands.

Private organizer tooling.  The flag never appears in any shipped artifact.
"""
import hashlib
import hmac
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
import gen_m06 as g6

MAGIC = b"NSCF"
VERSION = 0x0003
TOKEN = g6.DISPATCH_TOKEN

C2_HOST = "198.51.100.7"
C2_PORT = 4444
SESSION_ID = hashlib.sha256(b"nightshift-c2-session-v1").digest()[:16]
DECOY_SID = hashlib.sha256(b"nightshift-c2-decoy-session").digest()[:16]

BAIT = "FTA{n1ghtsh1ft_c2_c0nf1g_b41t_d0_n0t_subm1t}"

# ---- smeared key material (heap allocations) ------------------------------
B0 = bytes.fromhex("a1b2c3d4e5f60718")
B1 = bytes.fromhex("1122334455667788")
B2 = bytes.fromhex("deadbeefcafebabe")
B3 = bytes.fromhex("0f1e2d3c4b5a6978")
STUF = bytes.fromhex("9988776655443322")          # live scratch (not key)
B2T = bytearray(B2)
B2T[3] ^= 0x01                                     # trap: one nibble differs
B2T = bytes(B2T)


def xor_all(bufs):
    r = bytearray(len(bufs[0]))
    for b in bufs:
        for i in range(len(r)):
            r[i] ^= b[i]
    return bytes(r)


RAM_KEY_LIVE = xor_all([B0, B1, B2, B3])
RAM_KEY_TRAP = xor_all([B0, B1, B2T, B3])


def kdf(token: bytes, ram_key: bytes) -> bytes:
    return hashlib.sha256(b"NS-CFG-KEY" + token + ram_key).digest()


def mac_key(key: bytes) -> bytes:
    return hashlib.sha256(b"NS-CFG-MAC" + key).digest()


def mac(key: bytes, data: bytes) -> bytes:
    return hmac.new(mac_key(key), data, hashlib.sha256).digest()[:16]


def keystream(key: bytes, n: int, iv: bytes) -> bytes:
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(key + iv + struct.pack("<I", i)).digest()
        i += 1
    return bytes(out[:n])


def xor_key(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def enc_blob(key: bytes, pt: bytes, iv: bytes) -> bytes:
    ct = xor_key(pt, keystream(key, len(pt), iv))
    return iv + ct + mac(key, iv + ct)


def dec_blob(key: bytes, blob: bytes) -> bytes:
    iv, ct, tag = blob[:8], blob[8:-16], blob[-16:]
    if mac(key, iv + ct) != tag:
        raise ValueError("config section failed its authentication tag")
    return xor_key(ct, keystream(key, len(ct), iv))


IV_LIVE = hashlib.sha256(b"NS-CFG-IV-live").digest()[:8]
IV_LEGC = hashlib.sha256(b"NS-CFG-IV-legc").digest()[:8]


# ---------------------------------------------------------------------------
# heap slice
# ---------------------------------------------------------------------------
RAM_RECS = [(b"KEY0", 1, B0), (b"KEY1", 1, B1), (b"KEY2", 1, B2),
            (b"KEY3", 1, B3), (b"TMP0", 1, STUF), (b"K2SH", 0, B2T),
            (b"JUNK", 0, b"\x00" * 8)]


def build_ram_slice() -> bytes:
    out = bytearray(b"NSRAM1" + struct.pack("<H", 1) + struct.pack("<H", len(RAM_RECS)))
    for name, status, data in RAM_RECS:
        chk = (sum(data) ^ 0x5A) & 0xFF
        out += name + bytes([status]) + data + bytes([chk]) + b"\x00\x00"
    return bytes(out)


# ---------------------------------------------------------------------------
# config container
# ---------------------------------------------------------------------------
def build_config(flag2: str) -> bytes:
    live_txt = ("NSCFG build=live\n"
                "FLAG:" + flag2 + "\n"
                "C2:" + C2_HOST + ":" + str(C2_PORT) + "\n"
                "SESSION:" + SESSION_ID.hex() + "\n").encode("ascii")
    legc_txt = ("NSCFG build=legacy\n"
                "FLAG:" + BAIT + "\n"
                "C2:203.0.113.9:4445\n"
                "SESSION:" + DECOY_SID.hex() + "\n").encode("ascii")

    tagv = mac(TOKEN, b"ns-config-tag")
    legc = enc_blob(kdf(TOKEN, RAM_KEY_TRAP), legc_txt, IV_LEGC)
    live = enc_blob(kdf(TOKEN, RAM_KEY_LIVE), live_txt, IV_LIVE)

    out = bytearray(MAGIC + struct.pack("<H", VERSION))
    for tag, data in ((b"TAGV", tagv), (b"LEGC", legc), (b"LIVE", live)):
        out += tag + struct.pack("<I", len(data)) + data
    return bytes(out)


NOTES = """NIGHTSHIFT CONFIG -- RECOVERY NOTE
=================================

We pulled two artifacts before the handset died: the implant's configuration
(nightshift_config.bin) and a raw slice of the process heap (ram_slice.bin).

The config is sealed with the loader's dispatch token from Part 1.  A 16-byte
tag at the top of the file will only agree if the token is right -- use it to
confirm before you waste time on the body.

The heap slice is a run of fixed 16-byte allocation records: a 4-character
name, one status byte (1 = live, 0 = freed), 8 payload bytes, and a one-byte
check over those 8 bytes.  Nothing is stored whole: the working key is smeared
across several allocations and has to be recombined.

Working theory, not yet confirmed
---------------------------------
  * use the retired shadow allocation, K2SH -- we were told the primary KEY2
    was recycled during the last reimage;
  * the section marked "legacy" is the one that carries the live config.

Deliverable: the config flag.  The live config also names the C2 endpoint and
the session id the third part is built on -- bring those forward.
"""


def main():
    out = L.out_dir("M07")
    flag = L.FLAGS["M07"]

    (out / "nightshift_config.bin").write_bytes(build_config(flag))
    (out / "ram_slice.bin").write_bytes(build_ram_slice())
    (out / "CONFIG_NOTES.txt").write_text(NOTES, encoding="utf-8")

    # ---- organizer self-checks -------------------------------------------
    # (0) the key smears: live vs trap vs "all live incl. scratch" all differ
    assert len(set([RAM_KEY_LIVE, RAM_KEY_TRAP,
                    xor_all([B0, B1, B2, B3, STUF])])) == 3

    # (1) the intended route opens the LIVE section with flag + C2 + session
    key_live = kdf(TOKEN, RAM_KEY_LIVE)
    cfg = build_config(flag)
    sec = parse_sections(cfg)
    assert sec[b"TAGV"] == mac(TOKEN, b"ns-config-tag"), "token tag mismatch"
    live = dec_blob(key_live, sec[b"LIVE"])
    assert flag.encode() in live
    assert (C2_HOST + ":" + str(C2_PORT)).encode() in live
    assert SESSION_ID.hex().encode() in live

    # (2) the note's route (shadow buffer + legacy section) yields the bait
    key_trap = kdf(TOKEN, RAM_KEY_TRAP)
    legc = dec_blob(key_trap, sec[b"LEGC"])
    assert BAIT.encode() in legc and flag.encode() not in legc
    # legacy does NOT open under the live key, and live does NOT open under trap
    for k, t in ((key_live, b"LEGC"), (key_trap, b"LIVE")):
        try:
            dec_blob(k, sec[t])
            raise AssertionError("cross-section key unexpectedly opened %r" % t)
        except ValueError:
            pass

    # (3) the wrong token fails the tag gate
    assert mac(b"\x00" * 16, b"ns-config-tag") != sec[b"TAGV"]

    # (4) no shipped artifact leaks the flag
    for name in ("nightshift_config.bin", "ram_slice.bin", "CONFIG_NOTES.txt"):
        blob = (out / name).read_bytes()
        assert flag.encode() not in blob, name

    print("[M07] wrote %s" % out)
    print("[M07] config=%d bytes  ram=%d bytes  c2=%s:%d  sid=%s..."
          % (len(cfg), len(build_ram_slice()), C2_HOST, C2_PORT, SESSION_ID.hex()[:8]))


def parse_sections(buf: bytes):
    assert buf.startswith(MAGIC)
    i = len(MAGIC) + 2
    sec = {}
    while i + 8 <= len(buf):
        tag = buf[i:i + 4]
        ln = struct.unpack("<I", buf[i + 4:i + 8])[0]
        i += 8
        sec[tag] = buf[i:i + ln]
        i += ln
    return sec


if __name__ == "__main__":
    main()
