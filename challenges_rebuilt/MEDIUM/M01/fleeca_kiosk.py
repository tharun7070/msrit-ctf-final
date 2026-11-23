#!/usr/bin/env python3
"""Fleeca Trusted Kiosk v2.3 - offline locker terminal (fictional lab).

Single-file local simulation. Runs against the bundled fleeca.db. No network,
no real accounts. Commands:
    register <user> <pw>   open a locker account
    login    <user> <pw>   authenticate a teller session
    load     <user>        read a locker profile / vault receipts
"""
import base64
import hashlib
import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
DB = HERE / "fleeca.db"
SESSION = HERE / ".fleeca_session"
SALT = "GTA_SALT_v2"


def pw_hash(password: str, username: str) -> str:
    return hashlib.sha256((password + username[::-1] + SALT).encode()).hexdigest()[:16]


def _conn():
    return sqlite3.connect(DB)


def register(username: str, password: str) -> int:
    """Open a new locker account. Stage 1: parameterized insert (safe)."""
    h = pw_hash(password, username)
    con = _conn()
    try:
        con.execute("INSERT INTO users(username, pw_hash) VALUES (?, ?)", (username, h))
        con.commit()
    except sqlite3.IntegrityError as e:
        print(f"register: account rejected ({e})")
        return 1
    finally:
        con.close()
    print(f"register: locker opened for {username!r}")
    return 0


def login(username: str, password: str) -> int:
    con = _conn()
    row = con.execute("SELECT pw_hash FROM users WHERE username = ?", (username,)).fetchone()
    con.close()
    if not row:
        print("login: unknown account")
        return 1
    if pw_hash(password, username) != row[0]:
        print("login: invalid credentials")
        return 1
    token = hashlib.sha256(f"kiosk|{username}|{row[0]}".encode()).hexdigest()
    SESSION.write_text(f"{username}:{token}", encoding="utf-8")
    print(f"login: welcome back, {username}")
    return 0


def _session_ok() -> bool:
    if not SESSION.exists():
        return False
    try:
        user, token = SESSION.read_text(encoding="utf-8").split(":", 1)
    except ValueError:
        return False
    con = _conn()
    row = con.execute("SELECT pw_hash FROM users WHERE username = ?", (user,)).fetchone()
    con.close()
    if not row:
        return False
    return token == hashlib.sha256(f"kiosk|{user}|{row[0]}".encode()).hexdigest()


def load_profile(username: str) -> int:
    """Stage 2: fetch the STORED username, then drop it straight into a raw query."""
    con = _conn()
    row = con.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone()
    if not row:
        con.close()
        print("load: no such locker")
        return 1
    stored = row[0]
    # Legacy vault lookup: the stored owner string is interpolated unescaped.
    query = f"SELECT owner, secret FROM vault WHERE owner = '{stored}'"
    try:
        rows = con.execute(query).fetchall()
    except sqlite3.Error as e:
        con.close()
        print(f"load: vault error ({e})")
        return 1
    con.close()
    print(f"load: profile for {stored!r}")
    if not _session_ok():
        print("load: session not authenticated - vault receipts masked")
        for owner, _ in rows:
            print(f"  owner={owner} secret=[masked]")
        return 0
    for owner, secret in rows:
        try:
            shown = base64.b64decode(secret.encode()).decode()
        except Exception:
            shown = secret
        print(f"  owner={owner} secret={shown}")
    return 0


def main(argv) -> int:
    usage = "usage: fleeca_kiosk.py {register <user> <pw>|login <user> <pw>|load <user>}"
    if len(argv) < 2:
        print(usage)
        return 2
    cmd = argv[1]
    if cmd == "register" and len(argv) == 4:
        return register(argv[2], argv[3])
    if cmd == "login" and len(argv) == 4:
        return login(argv[2], argv[3])
    if cmd == "load" and len(argv) == 3:
        return load_profile(argv[2])
    print(usage)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
