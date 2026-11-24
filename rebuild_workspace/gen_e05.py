#!/usr/bin/env python3
"""E05 - Wrong Extension, Right Exit (hardened multi-layer edition).

Produces `impound_dossier.pdf`, a TRIPLE-INTERPRETATION polyglot:

    [ PDF document ][ embedded GIF89a image ][ ZIP archive ]

so a quick `file` / `binwalk` guess is ambiguous. Inside the ZIP is an
AES-128-CBC encrypted SQLite vault. The whole scheme is stacked:

  1. TRIPLE POLYGLOT  : valid PDF (header/trailer) + valid ZIP (zipfile) +
                        a complete, valid embedded GIF89a image.
  2. TWO-FIELD KEY    : AES key = PBKDF2-HMAC-SHA256(serial + "|" + routecode,
                        salt, ITERS, 16). BOTH values must be pulled from the
                        PDF (a form-field serial AND a route code printed in
                        the visible body text). The IV is a THIRD independent
                        value carried in the ZIP extra field of the entry.
  3. SQLITE PUZZLE    : the decrypted vault has THREE tables that must be
                        joined on an unusual TEXT token; the flag is the XOR
                        of one hex column from each joined row (all three
                        required).
  4. DECOYS           : a fake flag planted in a decoy DB row, plus a fake
                        "revoked" AES key quoted in a PDF comment.

The flag never appears as raw ASCII anywhere in the output file. All randomness
is drawn from a fixed seed, so generation is byte-for-byte reproducible.
Private organizer tooling.
"""
import hashlib
import io
import os
import random
import sqlite3
import struct
import sys
import tempfile
import zipfile
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

SEED = 0xE05A1B
ITERS = 50000
DB_ENTRY = "vault.db.enc"

# --- the two PDF-sourced secrets (participant must extract these) -----------
SERIAL = "LSPD-4471-9A7C"          # lives in the PDF form field named "serial"
ROUTE_CODE = "RC-2026-7734"        # printed in the visible PDF body text
SALT = hashlib.sha256(b"E05-salt-v1").digest()[:16]

# --- decoys -----------------------------------------------------------------
FAKE_KEY_HEX = "00112233445566778899aabbccddeeff"   # grep-able PDF comment
FAKE_FLAG = "FTA{d3c0y_s34l5_n0t_th3_fl4g_2026}"    # decoy DB row


# ---------------------------------------------------------------------------
# Layer 1a: a complete, valid 1x1 GIF89a image (43 bytes).
# ---------------------------------------------------------------------------
def make_gif():
    b = bytearray()
    b += b"GIF89a"                                          # header
    b += struct.pack("<HH", 1, 1)                           # logical screen w,h
    b += bytes([0x80, 0x00, 0x00])                          # packed, bg, aspect
    b += bytes([0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF])        # 2-entry GCT
    b += bytes([0x21, 0xF9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00])  # GCE
    b += bytes([0x2C]) + struct.pack("<HHHH", 0, 0, 1, 1) + bytes([0x00])
    b += bytes([0x02, 0x02, 0x44, 0x01, 0x00])              # LZW data sub-block
    b += bytes([0x3B])                                      # trailer
    return bytes(b)


def validate_gif(b):
    """Structural validation of a GIF by walking its block stream."""
    if b[:6] not in (b"GIF89a", b"GIF87a"):
        return False
    i = 6
    if i + 7 > len(b):
        return False
    packed = b[i + 4]
    i += 7
    if packed & 0x80:
        i += 3 * (2 ** ((packed & 0x07) + 1))
    seen_image = False
    while i < len(b):
        blk = b[i]
        if blk == 0x3B:                      # trailer
            return seen_image
        if blk == 0x21:                      # extension: 0x21, label, sub-blocks
            i += 2
        elif blk == 0x2C:                    # image descriptor
            seen_image = True
            packed2 = b[i + 9]
            i += 10
            if packed2 & 0x80:
                i += 3 * (2 ** ((packed2 & 0x07) + 1))
            i += 1                           # LZW minimum code size
        else:
            return False
        # consume sub-blocks up to the 0x00 terminator
        while i < len(b) and b[i] != 0x00:
            i += 1 + b[i]
        i += 1
    return False


# ---------------------------------------------------------------------------
# Layer 1b: the PDF, incl. an AcroForm text field carrying the serial.
# ---------------------------------------------------------------------------
def _esc(s):
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def make_pdf(lines, serial):
    body = ["BT /F1 12 Tf 60 740 Td 16 TL"]
    for ln in lines:
        body.append(f"({_esc(ln)}) Tj T*")
    body.append("ET")
    content = "\n".join(body).encode("latin-1")

    objs = [
        b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [6 0 R 7 0 R] "
        b"/DA (/Helv 0 Tf 0 g) /NeedAppearances true >> >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R "
        b"/Resources << /Font << /F1 5 0 R >> >> /Annots [6 0 R 7 0 R] >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n"
        + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (serial) /V ("
        + serial.encode("latin-1") + b") /Rect [60 690 300 710] /P 3 0 R /F 4 "
        b"/DA (/Helv 12 Tf 0 g) >>",
        b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (prior_serial) "
        b"/V (0000-VOID-0000) /Rect [60 664 300 684] /P 3 0 R /F 4 "
        b"/DA (/Helv 12 Tf 0 g) >>",
    ]

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    # grep-able decoy: a revoked key that is NOT the real one
    out += b"% ARCHIVE KEY (revoked 2024-11, superseded - do not use): " \
           + FAKE_KEY_HEX.encode() + b"\n"
    out += b"% integrity note: a decoy flag is present downstream.\n"
    offsets = []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += str(i).encode() + b" 0 obj\n" + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 " + str(len(objs) + 1).encode() + b"\n"
    out += b"0000000000 65535 f \n"
    for off in offsets:
        out += f"{off:010d} 00000 n \n".encode()
    out += (b"trailer\n<< /Size " + str(len(objs) + 1).encode()
            + b" /Root 1 0 R >>\nstartxref\n" + str(xref).encode() + b"\n%%EOF\n")
    return bytes(out)


def fix_zip_offsets(zb, delta):
    """Rewrite central-directory offsets so the archive survives a prefix."""
    b = bytearray(zb)
    i = 0
    while True:
        i = b.find(b"PK\x01\x02", i)
        if i < 0:
            break
        off = int.from_bytes(b[i + 42:i + 46], "little")
        b[i + 42:i + 46] = (off + delta).to_bytes(4, "little")
        i += 4
    j = b.rfind(b"PK\x05\x06")
    cd_off = int.from_bytes(b[j + 16:j + 20], "little")
    b[j + 16:j + 20] = (cd_off + delta).to_bytes(4, "little")
    return bytes(b)


# ---------------------------------------------------------------------------
# Layer 3: the three-table SQLite vault.
# ---------------------------------------------------------------------------
def xor3(a, b, c):
    return bytes(x ^ y ^ z for x, y, z in zip(a, b, c))


def build_vault_db(token, flag):
    """Build the vault on a throwaway file and return its bytes."""
    flag_b = flag.encode()
    n = len(flag_b)

    rnd = random.Random(SEED ^ 0x5EED)

    def stream():
        return bytes(rnd.randrange(256) for _ in range(n))

    # A ^ B ^ C == flag, with each of the three stored values independent.
    s1, s2 = stream(), stream()
    A = bytes(x ^ y for x, y in zip(flag_b, s1))
    B = bytes(x ^ y for x, y in zip(s1, s2))
    C = s2

    d1, d2, d3 = "aa11", "deadbeef", "beefcafe"

    tmpdir = tempfile.mkdtemp(prefix="e05db_")
    p = Path(tmpdir) / "vault.db"
    con = sqlite3.connect(str(p))
    con.executescript(
        """
        CREATE TABLE operators (op_id INTEGER PRIMARY KEY, handle TEXT,
                                token TEXT, clearance TEXT, mask_hex TEXT);
        CREATE TABLE routes    (rt_id INTEGER PRIMARY KEY, token TEXT,
                                leg INTEGER, corridor TEXT, stream_hex TEXT);
        CREATE TABLE seals     (seal_id INTEGER PRIMARY KEY, token TEXT,
                                grade TEXT, seal_hex TEXT, note TEXT);
        """)
    con.executemany("INSERT INTO operators VALUES (?,?,?,?,?)", [
        (4471, "Sgt. R. Vasquez", token, "A", A.hex()),
        (1102, "M. Cruz", d1, "C", stream().hex()),
        (2207, "J. Okafor", d2, "B", stream().hex()),
    ])
    con.executemany("INSERT INTO routes VALUES (?,?,?,?,?)", [
        (21, token, 3, "north-loop", B.hex()),
        (22, d1, 1, "harbor-spur", stream().hex()),
        (23, d3, 2, "dockside", stream().hex()),
    ])
    con.executemany("INSERT INTO seals VALUES (?,?,?,?,?)", [
        (77, token, "A", C.hex(), "sealed wallet manifest (genuine seal)"),
        (88, d2, "B", stream().hex(),
         "DECOY seal - revoked reference " + FAKE_FLAG),
        (99, d3, "C", stream().hex(), "unlabelled container, no manifest"),
    ])
    con.commit()
    con.close()
    data = p.read_bytes()
    try:
        os.unlink(p)
        os.rmdir(tmpdir)
    except OSError:
        pass
    return data


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def _zi(name, extra=b""):
    zi = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    zi.compress_type = zipfile.ZIP_STORED
    zi.external_attr = 0o600 << 16
    zi.extra = extra
    return zi


def main():
    out = L.out_dir("E05")
    flag = L.FLAGS["E05"]

    rnd = random.Random(SEED)
    iv = bytes(rnd.randrange(256) for _ in range(16))          # 3rd source
    token = "%08x" % rnd.randrange(1 << 32)                    # unusual join key

    # --- 3-table vault, then AES-128-CBC encrypt the whole DB ---
    db_bytes = build_vault_db(token, flag)
    key = hashlib.pbkdf2_hmac(
        "sha256", (SERIAL + "|" + ROUTE_CODE).encode(), SALT, ITERS, 16)
    enc_bytes = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(db_bytes, 16))

    readme = (
        "Fleeca impound release package - courier manifest (private).\n"
        "\n"
        "This single file is a PDF, a ZIP archive and a GIF image at once.\n"
        "Rename it to .zip (or carve the archive) to read the entries.\n"
        "\n"
        "Entries:\n"
        "  %s  AES-128-CBC(PKCS#7) of the seizure database (vault.db).\n"
        "            The IV is NOT prefixed to the ciphertext; it is carried\n"
        "            in this entry's ZIP extra field, header id \"FT\" (0x4654).\n"
        "  readme.txt  this note.\n"
        "\n"
        "KDF-SPEC\n"
        "  key = PBKDF2-HMAC-SHA256(password = SERIAL + \"|\" + ROUTE_CODE,\n"
        "                           salt = %s,\n"
        "                           iterations = %d, dklen = 16)\n"
        "  SERIAL     : the value of the PDF form field named \"serial\"\n"
        "               (parse the field; it is not printed in the body).\n"
        "  ROUTE_CODE : the route code printed in the visible form body text.\n"
        "  A revoked legacy key (NOT this one) is quoted in a PDF comment.\n"
        "\n"
        "Recovered vault.db holds three tables: operators, routes, seals.\n"
        "Join them on the text token column (all three are required), then XOR\n"
        "the three *_hex columns of the correctly joined rows to unseal the\n"
        "value. Beware: a decoy flag was planted inside a decoy row.\n"
        % (DB_ENTRY, SALT.hex(), ITERS))

    extra = b"FT" + struct.pack("<H", 16) + iv
    zio = io.BytesIO()
    with zipfile.ZipFile(zio, "w") as z:
        z.writestr(_zi(DB_ENTRY, extra=extra), enc_bytes)
        z.writestr(_zi("readme.txt"), readme.encode())
    zip_bytes = zio.getvalue()

    # --- the PDF body (serial only in the field; route code only in text) ---
    pdf = make_pdf([
        "LOS SANTOS POLICE DEPARTMENT - IMPOUND RELEASE FORM",
        "Case: FTA-2026-1104        Vehicle: Declasse Voodoo (orange)",
        "",
        "Declared contents: folded furniture, personal effects.",
        "Route code: " + ROUTE_CODE + "        Bay: C-09",
        "Custody officer note: paperwork does not match the cargo weight.",
        "",
        "This document is the release slip only. The seized evidence",
        "manifest travels attached (right of the %%EOF marker).",
        "",
        "Authorised by: Sgt. R. Vasquez   Badge 4471",
        "Encryption key is derived from the field value and the route code.",
    ], serial=SERIAL)

    gif = make_gif()
    prefix = len(pdf) + len(gif)
    polyglot = pdf + gif + fix_zip_offsets(zip_bytes, prefix)
    (out / "impound_dossier.pdf").write_bytes(polyglot)

    # ------------------------------------------------------------------ verify
    assert polyglot[:5] == b"%PDF-"
    assert b"trailer" in polyglot and b"startxref" in polyglot and b"%%EOF" in polyglot
    assert validate_gif(polyglot[len(pdf):len(pdf) + len(gif)])
    assert flag.encode() not in polyglot, "flag leaked as raw ASCII!"
    with zipfile.ZipFile(io.BytesIO(polyglot)) as z:
        assert z.read(DB_ENTRY) == enc_bytes
        got_extra = z.getinfo(DB_ENTRY).extra
        assert got_extra[:2] == b"FT"
        iv_back = got_extra[4:4 + struct.unpack("<H", got_extra[2:4])[0]]
        assert iv_back == iv
        pt = unpad(AES.new(key, AES.MODE_CBC, iv_back).decrypt(z.read(DB_ENTRY)), 16)
        assert pt == db_bytes
    print("[E05] polyglot %d bytes (pdf %d + gif %d + zip %d)"
          % (len(polyglot), len(pdf), len(gif), len(zip_bytes)))
    print("[E05] layers: PDF + GIF89a + ZIP | PBKDF2(two PDF fields) | "
          "IV in ZIP extra | 3-table SQLite XOR | decoys")


if __name__ == "__main__":
    main()
