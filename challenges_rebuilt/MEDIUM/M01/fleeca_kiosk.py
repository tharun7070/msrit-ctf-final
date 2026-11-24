#!/usr/bin/env python3
"""Fleeca Trusted Kiosk v3.1 - offline locker terminal (fictional lab).

Single-file local simulation. Runs against the bundled fleeca.db. No network,
no real accounts. Commands:
    register <user> <pw>   open a locker account
    login    <user> <pw>   authenticate a teller session
    sync     <user>        derive an account's display alias into the registry
    load     <user>        read a locker profile / vault receipts
"""
import base64
import hashlib
import hmac
import os
import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DB = HERE / "fleeca.db"
SESSION = HERE / ".fleeca_session"
HASH_TAG = "fleeca-h2"
VEIL_TAG = "M01-escrow-veil"
LEGACY_LEDGER = "vault"
CANARY_LEDGER = "escrow"


def _conn():
    return sqlite3.connect(DB)


def _cfg(con, key):
    row = con.execute("SELECT value FROM config WHERE key = ?", (key,)).fetchone()
    return row[0] if row else ""


def _hash(password, username, salt, pepper):
    material = f"{HASH_TAG}|{salt}|{password}|{username[::-1]}|{pepper}"
    return hashlib.sha256(material.encode()).hexdigest()[:20]


def pw_hash(password, username):
    con = _conn()
    row = con.execute("SELECT pw_salt FROM users WHERE username = ?", (username,)).fetchone()
    pepper = _cfg(con, "server_pepper")
    con.close()
    if not row:
        return None
    return _hash(password, username, row[0], pepper)


def register(username, password):
    """Stage 1: parameterized insert (safe)."""
    con = _conn()
    pepper = _cfg(con, "server_pepper")
    salt = os.urandom(8).hex()
    h = _hash(password, username, salt, pepper)
    try:
        con.execute(
            "INSERT INTO users(username, pw_hash, pw_salt, role) VALUES (?, ?, ?, ?)",
            (username, h, salt, "teller"),
        )
        con.commit()
    except sqlite3.IntegrityError as e:
        con.close()
        print(f"register: account rejected ({e})")
        return 1
    con.close()
    print(f"register: locker opened for {username!r}")
    return 0


def login(username, password):
    con = _conn()
    row = con.execute("SELECT pw_hash FROM users WHERE username = ?", (username,)).fetchone()
    secret = _cfg(con, "session_key")
    con.close()
    if not row:
        print("login: unknown account")
        return 1
    if pw_hash(password, username) != row[0]:
        print("login: invalid credentials")
        return 1
    nonce = os.urandom(8).hex()
    token = hmac.new(bytes.fromhex(secret), f"{username}|{nonce}".encode(), hashlib.sha256).hexdigest()
    SESSION.write_text(f"{username}:{nonce}:{token}", encoding="utf-8")
    print(f"login: welcome back, {username}")
    return 0


def _session_ok():
    if not SESSION.exists():
        return False
    try:
        user, nonce, token = SESSION.read_text(encoding="utf-8").split(":", 2)
    except ValueError:
        return False
    con = _conn()
    row = con.execute("SELECT pw_hash FROM users WHERE username = ?", (user,)).fetchone()
    secret = _cfg(con, "session_key")
    con.close()
    if not row:
        return False
    expect = hmac.new(bytes.fromhex(secret), f"{user}|{nonce}".encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(token, expect)


def _rot13(text):
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))


def _display_alias(text):
    """Legacy alias transform applied on write: ROT13 then reverse."""
    return _rot13(text)[::-1]


def _scrub(s):
    """Stage 2 helper: legacy alias normaliser.

    Escapes single quotes SQL-style and drops the `--` line-comment and `;`
    separators. Doubled quotes are treated as an escape and are un-doubled for
    display when the alias is read back.
    """
    s = s.replace("'", "''")
    s = s.replace("--", "")
    s = s.replace(";", "")
    return s


def sync(username):
    """Stage 2: derive a display alias from the STORED username and persist it.

    This is a second stored operation: it reads the raw username and writes a
    transformed copy into the `profiles` registry.
    """
    con = _conn()
    row = con.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        con.close()
        print("sync: unknown account")
        return 1
    alias = _display_alias(_scrub(row[0]))
    con.execute(
        "INSERT INTO profiles(username, alias, updated) VALUES (?, ?, ?) "
        "ON CONFLICT(username) DO UPDATE SET alias = excluded.alias, updated = excluded.updated",
        (row[0], alias, 1),
    )
    con.commit()
    con.close()
    print(f"sync: alias registry updated for {username!r}")
    return 0


def _keystream(key, tag, length):
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(key + tag.encode() + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def _veil_key():
    con = _conn()
    secret = _cfg(con, "session_key")
    con.close()
    return hmac.new(bytes.fromhex(secret), VEIL_TAG.encode(), hashlib.sha256).digest()


def _unveil(blob, tag):
    raw = base64.b64decode(blob[3:])
    ks = _keystream(_veil_key(), tag, len(raw))
    return bytes(a ^ b for a, b in zip(raw, ks)).decode()


def _show(value, tag):
    """Display a stored column: unveil session-veiled values, else b64-decode
    (secrets only) or fall back to the raw text."""
    if value.startswith("v1:"):
        try:
            return _unveil(value, tag)
        except Exception:
            return value
    if tag == "secret":
        try:
            return base64.b64decode(value.encode()).decode()
        except Exception:
            return value
    return value


def load_profile(username):
    """Stage 3: fetch the STORED alias (never the raw username) and drop it
    straight into a raw, unparameterised query."""
    con = _conn()
    row = con.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        con.close()
        print("load: no such locker")
        return 1
    stored = row[0]
    prow = con.execute("SELECT alias FROM profiles WHERE username = ?", (stored,)).fetchone()
    if not prow:
        con.close()
        print("load: alias not synced for this account")
        return 1
    # Restore the escaped display text; the write-side display transform is NOT
    # undone here.
    alias = prow[0].replace("''", "'")
    # Canary: the "obvious" ledger is a trap. Querying it poisons the teller
    # session and serves decoy receipts.
    if CANARY_LEDGER in alias.lower():
        try:
            SESSION.write_text("poison:canary:tripped", encoding="utf-8")
        except OSError:
            pass
        dec = con.execute(f"SELECT owner, secret FROM {CANARY_LEDGER}").fetchall()
        con.close()
        print(f"load: profile for {stored!r}")
        for owner, secret in dec:
            print(f"  owner={owner} secret={_show(secret, 'secret')}")
        return 0
    query = f"SELECT owner, secret FROM {LEGACY_LEDGER} WHERE owner = '{alias}'"
    try:
        rows = con.execute(query).fetchall()
    except sqlite3.Error as e:
        con.close()
        print(f"load: vault error ({e})")
        return 1
    con.close()
    print(f"load: profile for {stored!r}")
    if not _session_ok():
        print("load: session not authenticated - vault receipts locked")
        for _owner, _secret in rows:
            print("  owner=[locked] secret=[locked]")
        return 0
    for owner, secret in rows:
        print(f"  owner={_show(owner, 'owner')} secret={_show(secret, 'secret')}")
    return 0


def main(argv):
    usage = ("usage: fleeca_kiosk.py {register <user> <pw>|login <user> <pw>"
             "|sync <user>|load <user>}")
    if len(argv) < 2:
        print(usage)
        return 2
    cmd = argv[1]
    if cmd == "register" and len(argv) == 4:
        return register(argv[2], argv[3])
    if cmd == "login" and len(argv) == 4:
        return login(argv[2], argv[3])
    if cmd == "sync" and len(argv) == 3:
        return sync(argv[2])
    if cmd == "load" and len(argv) == 3:
        return load_profile(argv[2])
    print(usage)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
