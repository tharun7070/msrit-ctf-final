#!/usr/bin/env python3
"""M06 - Nightshift Loader (Part 1 of 3): custom packer unwrap.

Ships a non-standard packed implant container (private magic ``NSLF`` -- not an
ELF and not any recognisable format), a misdirecting field note and a
deliberately short triage stub.

Packing pipeline (innermost first):

    payload  ->  custom base-40 ASCII text  ->  XOR against a SHA-256 counter
                 keystream keyed by BASE_KEY  ->  sectioned container with a
                 rotated key table (``KEYT``), the charset (``CHST``), the
                 sealed body + CRC32 (``PACK``) and a retained decoy build
                 record (``DBUG``).

Reversing the packer recovers the Part-1 flag AND the dispatch token that
Part 2 (M07) demands.

  * the header byte ``rort`` tells how far ``KEYT`` was turned; the table must
    be un-rotated before it is used (the note insists it is "used as stored");
  * the body is self-checking: only a read whose CRC32 agrees is genuine;
  * ``CHST`` holds the 40-character alphabet the body was re-encoded into;
  * ``DBUG`` is bait -- the note and the stub both decode it to a decoy flag.

Private organizer tooling.  The flag never appears in any shipped artifact.
"""
import base64
import hashlib
import struct
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

MAGIC = b"NSLF"
VERSION = 0x0002
RORT = 7
BASE_KEY = bytes.fromhex("1f2e3d4c5b6a798897a6b5c4d3e2f100")
ALPHABET = "z0q1m2p3v4x5k6b7n8w9_t!r@d#gcfhyjlasoeiu"
BASE = len(ALPHABET)

# The dispatch token that Part 2 keys its configuration with.
DISPATCH_TOKEN = hashlib.sha256(b"nightshift-dispatch-token-v1").digest()[:16]

# Bait: only reachable by the note/stub route (the retained debug record).
BAIT = "FTA{n1ghtsh1ft_l04d3r_d3bug_b41t_d0_n0t_subm1t}"

assert len(ALPHABET) == 40 and len(set(ALPHABET)) == 40


# ---------------------------------------------------------------------------
# primitives
# ---------------------------------------------------------------------------
def rotate_tab(key: bytes, r: int) -> bytes:
    r %= len(key)
    return key[r:] + key[:r]


def unrotate_tab(key: bytes, r: int) -> bytes:
    return rotate_tab(key, len(key) - (r % len(key)))


def keystream(key: bytes, n: int) -> bytes:
    out = bytearray()
    i = 0
    while len(out) < n:
        out += hashlib.sha256(key + struct.pack("<I", i)).digest()
        i += 1
    return bytes(out[:n])


def xor_key(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def b40_encode(b: bytes) -> str:
    v = int.from_bytes(b, "big")
    if v == 0:
        return ALPHABET[0]
    digs = []
    while v > 0:
        digs.append(ALPHABET[v % BASE])
        v //= BASE
    return "".join(reversed(digs))


def b40_decode(s: str) -> bytes:
    v = 0
    for ch in s:
        v = v * BASE + ALPHABET.index(ch)
    return v.to_bytes((v.bit_length() + 7) // 8, "big")


# ---------------------------------------------------------------------------
# container
# ---------------------------------------------------------------------------
def build_sections(payload: bytes):
    enc = b40_encode(payload).encode("ascii")
    body = xor_key(enc, keystream(BASE_KEY, len(enc)))
    # self-checking body: the CRC32 of the *decoded* text sits in the clear.
    pack = struct.pack("<I", zlib.crc32(enc) & 0xFFFFFFFF) + body

    keyt = rotate_tab(BASE_KEY, RORT)
    bait_txt = ("NS-DEBUG-BUILD 0x2\n"
                "cached dispatch flag: " + BAIT + "\n"
                "build: dev-nightly | do not ship\n").encode("ascii")
    dbug = base64.b64encode(xor_key(bait_txt, b"\x5a"))

    return [(b"KEYT", keyt), (b"CHST", ALPHABET.encode("ascii")),
            (b"PACK", pack), (b"DBUG", dbug)]


def build_container(payload: bytes) -> bytes:
    out = bytearray(MAGIC + struct.pack("<H", VERSION) + bytes([RORT]))
    for tag, data in build_sections(payload):
        out += tag + struct.pack("<I", len(data)) + data
    return bytes(out)


NOTES = """NIGHTSHIFT LOADER -- FIELD NOTE
==============================

The fixer's handset gave up a single blob we are calling the Nightshift
loader.  It is not an ELF and it is not any container our tools recognise --
the crew rolled their own, and this note is the only paperwork that survived.

What triage (unpack_stub.py) will tell you
------------------------------------------
  * the section table is authoritative and is walked in order;
  * the retained DBUG record is the cached build flag -- it is XOR-masked with
    0x5A and base64-encoded, and the stub prints it cleanly;
  * the KEYT table is the dispatch key, used exactly as it is stored.

What triage cannot read, and we have not cracked
------------------------------------------------
  * PACK is the live body.  It carries its own 32-bit checksum, so a correct
    read verifies itself and a wrong one does not: a route that disagrees with
    the checksum is wrong, however tidy its output looks.
  * CHST is not "reserved scratch".  Nobody will say what it is.
  * The header's spare byte was never documented.

Deliverable: the loader's dispatch flag.  The loader also embeds a dispatch
token -- the next drop (the config) will not open without it.
"""

STUB = '''#!/usr/bin/env python3
"""Nightshift loader -- triage stub (incomplete).

Walks the container's section table and dumps the retained debug build record
as described in LOADER_NOTES.txt.  It does not read the live PACK body.

Run:  python unpack_stub.py
"""
import base64
import struct
import sys
from pathlib import Path

MAGIC = b"NSLF"


def sections(buf):
    i = len(MAGIC) + 3            # magic(4) + version(2) + spare(1)
    out = []
    while i + 8 <= len(buf):
        tag = buf[i:i + 4]
        ln = struct.unpack("<I", buf[i + 4:i + 8])[0]
        i += 8
        out.append((tag, buf[i:i + ln]))
        i += ln
    return out


def main():
    here = Path(__file__).resolve().parent
    buf = (here / "nightshift_loader.bin").read_bytes()
    if not buf.startswith(MAGIC):
        print("not a Nightshift loader container")
        return
    sec = dict(sections(buf))
    for tag, data in sections(buf):
        print("section %-4s %5d bytes" % (tag.decode("latin1"), len(data)))
    # the field note says the cached build flag is XOR-masked with 0x5A and
    # base64-encoded -- that route decodes cleanly, so we trust it for now.
    dbg = base64.b64decode(sec[b"DBUG"])
    print("cached build flag:", bytes(b ^ 0x5A for b in dbg).decode("ascii", "replace"))


if __name__ == "__main__":
    sys.exit(main())
'''


def main():
    out = L.out_dir("M06")
    flag = L.FLAGS["M06"]

    payload = (b"NS-PAYLOAD v2\nFLAG:" + flag.encode("ascii")
               + b"\nTOKEN:" + DISPATCH_TOKEN.hex().encode("ascii") + b"\n")
    container = build_container(payload)
    (out / "nightshift_loader.bin").write_bytes(container)
    (out / "LOADER_NOTES.txt").write_text(NOTES, encoding="utf-8")
    (out / "unpack_stub.py").write_text(STUB, encoding="utf-8")

    # ---- organizer self-checks -------------------------------------------
    # (0) primitives round-trip
    assert unrotate_tab(rotate_tab(BASE_KEY, RORT), RORT) == BASE_KEY
    assert b40_decode(b40_encode(payload)) == payload, "base-40 round-trip failed"

    # (1) the intended route recovers the payload (flag + token)
    sec = dict(build_sections(payload))
    key = unrotate_tab(sec[b"KEYT"], RORT)
    pack = sec[b"PACK"]
    crc = struct.unpack("<I", pack[:4])[0]
    enc = xor_key(pack[4:], keystream(key, len(pack) - 4))
    assert zlib.crc32(enc) & 0xFFFFFFFF == crc, "CRC gate failed on the true route"
    assert b40_decode(enc.decode("ascii")) == payload
    assert flag.encode() in payload and DISPATCH_TOKEN.hex().encode() in payload

    # (2) using the key table "as stored" (the note's insistence) breaks the CRC
    bad_enc = xor_key(pack[4:], keystream(sec[b"KEYT"], len(pack) - 4))
    assert zlib.crc32(bad_enc) & 0xFFFFFFFF != crc, "rotated table must not verify"

    # (3) the decoy DBUG record yields the bait flag, never the real one
    dbg = base64.b64decode(sec[b"DBUG"])
    dbg_txt = xor_key(dbg, b"\x5a").decode("ascii")
    assert BAIT in dbg_txt and flag not in dbg_txt

    # (4) the triage stub runs cleanly and prints the bait, not the flag
    ns = {"__name__": "__main__", "__file__": str(out / "unpack_stub.py")}
    import contextlib
    import io
    buf_io = io.StringIO()
    with contextlib.redirect_stdout(buf_io):
        try:
            exec(compile(STUB, str(out / "unpack_stub.py"), "exec"), ns)
        except SystemExit:
            pass
    stub_out = buf_io.getvalue()
    assert BAIT in stub_out and flag not in stub_out, stub_out

    # (5) no shipped artifact may contain the flag or the token in the clear
    token_hex = DISPATCH_TOKEN.hex()
    for name in ("nightshift_loader.bin", "LOADER_NOTES.txt", "unpack_stub.py"):
        blob = (out / name).read_bytes()
        assert flag.encode() not in blob, name
        assert token_hex.encode() not in blob, name

    print("[M06] wrote %s" % out)
    print("[M06] container=%d bytes  sections=%d  rort=%d  token=%s..."
          % (len(container), len(sec), RORT, token_hex[:8]))


if __name__ == "__main__":
    main()
