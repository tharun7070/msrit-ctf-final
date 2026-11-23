#!/usr/bin/env python3
"""E05 reference solver: treat the .pdf as a ZIP polyglot, read the SQLite
key, AES-128-CBC decrypt the evidence blob."""
import io, os, re, sqlite3, sys, tempfile, zipfile
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L


def solve():
    path = L.out_dir("E05") / "impound_dossier.pdf"
    raw = path.read_bytes()
    assert raw[:5] == b"%PDF-", "not a PDF header"
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        names = z.namelist()
        assert "vault.db" in names and "vault.enc" in names, names
        db_bytes = z.read("vault.db")
        blob = z.read("vault.enc")
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        tf.write(db_bytes)
        tmppath = tf.name
    con = sqlite3.connect(tmppath)
    key_hex = con.execute("SELECT v FROM vault_meta WHERE k='key_hex'").fetchone()[0]
    con.close()
    os.unlink(tmppath)
    key = bytes.fromhex(key_hex)
    iv, ct = blob[:16], blob[16:]
    pt = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(ct), 16)
    flag = re.search(r"FTA\{[a-z0-9_]+\}", pt.decode()).group(0)
    assert flag == L.FLAGS["E05"], flag
    print("[E05] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
