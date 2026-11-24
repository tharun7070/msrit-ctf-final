#!/usr/bin/env python3
"""E05 reference solver (hardened).

Inverts every stacked layer of `impound_dossier.pdf`:

  1. carve the ZIP out of the PDF/GIF/ZIP polyglot;
  2. read the KDF spec from readme.txt, pull SERIAL from the PDF form field and
     ROUTE_CODE from the visible body text, derive the AES key with
     PBKDF2-HMAC-SHA256, and take the IV from the entry's ZIP extra field;
  3. decrypt vault.db.enc -> vault.db;
  4. join operators/routes/seals on the text token and XOR the three *_hex
     columns of the single joined row to recover the flag.
"""
import hashlib
import io
import os
import re
import sqlite3
import struct
import sys
import tempfile
import zipfile
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L


def xor3(a, b, c):
    return bytes(x ^ y ^ z for x, y, z in zip(a, b, c))


def solve():
    raw = (L.out_dir("E05") / "impound_dossier.pdf").read_bytes()
    assert raw[:5] == b"%PDF-", "not a PDF header"

    # --- layer 2: two PDF-sourced fields --------------------------------------
    m = re.search(rb"/T\s*\(serial\)[^>]*?/V\s*\(([^)]*)\)", raw, re.S)
    assert m, "serial form field not found"
    serial = m.group(1).decode("latin-1")
    m = re.search(rb"Route code:\s*([A-Za-z0-9\-]+)", raw)
    assert m, "route code not found in body"
    route = m.group(1).decode("latin-1")

    # --- layer 1: pull the ZIP out of the polyglot ----------------------------
    z = zipfile.ZipFile(io.BytesIO(raw))
    names = z.namelist()
    assert "vault.db.enc" in names and "readme.txt" in names, names
    readme = z.read("readme.txt").decode()

    salt = bytes.fromhex(re.search(r"salt\s*=\s*([0-9a-fA-F]+)", readme).group(1))
    iters = int(re.search(r"iterations\s*=\s*(\d+)", readme).group(1))

    # IV lives in the encrypted entry's ZIP extra field (header id "FT").
    extra = z.getinfo("vault.db.enc").extra
    i = extra.find(b"FT")
    assert i >= 0, "FT extra field missing"
    ln = struct.unpack("<H", extra[i + 2:i + 4])[0]
    iv = extra[i + 4:i + 4 + ln]
    assert len(iv) == 16, iv

    key = hashlib.pbkdf2_hmac("sha256", (serial + "|" + route).encode(),
                              salt, iters, 16)

    # --- layer: decrypt the vault --------------------------------------------
    db_bytes = unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(z.read("vault.db.enc")), 16)
    z.close()

    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.write(db_bytes)
    tmp.close()
    con = sqlite3.connect(tmp.name)
    rows = con.execute(
        "SELECT o.token, o.mask_hex, r.stream_hex, s.seal_hex "
        "FROM operators o "
        "JOIN routes r ON r.token = o.token "
        "JOIN seals  s ON s.token = o.token").fetchall()
    con.close()
    os.unlink(tmp.name)

    # --- layer 3: 3-table XOR derivation --------------------------------------
    flags = []
    for token, mask_hex, stream_hex, seal_hex in rows:
        cand = xor3(bytes.fromhex(mask_hex), bytes.fromhex(stream_hex),
                    bytes.fromhex(seal_hex))
        try:
            text = cand.decode("ascii")
        except UnicodeDecodeError:
            continue
        m = re.search(r"FTA\{[a-z0-9_]+\}", text)
        if m:
            flags.append(m.group(0))

    assert len(set(flags)) == 1, ("unexpected candidate set", flags)
    flag = flags[0]
    assert flag == L.FLAGS["E05"], (flag, L.FLAGS["E05"])
    print("[E05] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
