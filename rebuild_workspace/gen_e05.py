#!/usr/bin/env python3
"""E05 — Wrong Extension, Right Exit (PDF/ZIP polyglot + AES + SQLite trail).

Produces `impound_dossier.pdf`:
  * valid single-page PDF when opened normally;
  * valid ZIP when renamed to .zip / opened by an archiver, containing:
      - vault.db    : SQLite DB carrying the AES key + scheme notes;
      - vault.enc   : IV (first 16 bytes) || AES-128-CBC ciphertext of the flag;
      - readme.txt  : short field note.
The ZIP central-directory offsets are patched so the archive survives the
prepended PDF bytes. Private organizer tooling.
"""
import io, sqlite3, struct, sys, zipfile
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L


def make_pdf(lines):
    def esc(s):
        return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")
    body = ["BT /F1 12 Tf 60 740 Td 16 TL"]
    for ln in lines:
        body.append(f"({esc(ln)}) Tj T*")
    body.append("ET")
    content = "\n".join(body).encode("latin-1")

    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length " + str(len(content)).encode() + b" >>\nstream\n"
        + content + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
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


def main():
    out = L.out_dir("E05")
    import hashlib, os
    key = hashlib.sha256(b"fleeca-impound-2026" + L.FLAGS["E05"].encode()).digest()[:16]
    key_hex = key.hex()

    # --- build the SQLite vault on a real file ---
    dbpath = out / "vault.db"
    if dbpath.exists():
        dbpath.unlink()
    con = sqlite3.connect(dbpath)
    con.executescript(
        """
        CREATE TABLE vault_meta (k TEXT PRIMARY KEY, v TEXT);
        CREATE TABLE seized_items (tag TEXT, note TEXT);
        INSERT INTO vault_meta VALUES ('format','AES-128-CBC');
        INSERT INTO vault_meta VALUES ('key_hex','PLACEHOLDER');
        INSERT INTO vault_meta VALUES ('iv','first 16 bytes of vault.enc');
        INSERT INTO vault_meta VALUES ('padding','PKCS#7');
        INSERT INTO vault_meta VALUES ('note','Declared cargo was a folding chair.');
        INSERT INTO seized_items VALUES ('LP-4471','folding chair (x1)');
        INSERT INTO seized_items VALUES ('LP-4472','unlabelled hard drive');
        INSERT INTO seized_items VALUES ('LP-4473','bag of loose SIM cards');
        """)
    con.execute("UPDATE vault_meta SET v=? WHERE k='key_hex'", (key_hex,))
    con.commit()
    con.close()
    db_bytes = dbpath.read_bytes()
    dbpath.unlink()

    # --- AES-128-CBC encrypted evidence blob (iv || ct) ---
    iv = bytes(range(16))
    plaintext = ("IMPOUND EVIDENCE / SEALED WALLET\n"
                 f"recovered_flag={L.FLAGS['E05']}\n").encode()
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, 16))
    enc_bytes = iv + ct

    readme = ("Fleeca vault seizure package.\n"
              "If you can read this as text, rename the file to .zip.\n"
              "vault.db  - manifest of encryption parameters.\n"
              "vault.enc - iv (16 bytes) followed by AES-128-CBC ciphertext.\n")

    # --- assemble the ZIP payload in memory (stored, no compression) ---
    zio = io.BytesIO()
    with zipfile.ZipFile(zio, "w", zipfile.ZIP_STORED) as z:
        z.writestr("vault.db", db_bytes)
        z.writestr("vault.enc", enc_bytes)
        z.writestr("readme.txt", readme)
    zip_bytes = zio.getvalue()

    pdf = make_pdf([
        "LOS SANTOS POLICE DEPARTMENT - IMPOUND RELEASE FORM",
        "Case: FTA-2026-1104        Vehicle: Declasse Voodoo (orange)",
        "",
        "Declared contents: folded furniture, personal effects.",
        "Custody officer note: paperwork does not match the cargo weight.",
        "",
        "This document is the release slip only. The seized evidence",
        "manifest travels attached (right of the %%EOF marker).",
        "",
        "Authorised by: Sgt. R. Vasquez   Badge 4471",
    ])
    polyglot = pdf + fix_zip_offsets(zip_bytes, len(pdf))
    (out / "impound_dossier.pdf").write_bytes(polyglot)

    # round-trip verification
    with zipfile.ZipFile(io.BytesIO(polyglot)) as z:
        assert z.read("vault.db") == db_bytes
        assert z.read("vault.enc") == enc_bytes
    print(f"[E05] polyglot {len(polyglot)} bytes (pdf {len(pdf)} + zip {len(zip_bytes)})")


if __name__ == "__main__":
    main()
