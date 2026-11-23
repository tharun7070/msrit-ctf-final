#!/usr/bin/env python3
"""M01 - Fleeca Vault Glitch. Generator (private organizer tooling).

Produces the participant artifacts in L.out_dir("M01"):
  - fleeca_kiosk.py : vulnerable offline terminal (second-order SQLi + custom hash auth)
  - fleeca.db       : sqlite snapshot (users + vault); flag row stored base64-encoded
  - common_pw.txt   : leaked wordlist containing the weak admin password

The raw flag string is NEVER written to any participant file: the vault stores
it base64-encoded and the kiosk de-escrows it on display at runtime only.
"""
import base64
import hashlib
import random
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, r"d:\ctf\FLAG_THEFT_AUTO_FINAL\rebuild_workspace")
import lib_fta as L

FLAG = L.FLAGS["M01"]
SALT = "GTA_SALT_v2"
ADMIN_PW = "sunshine"


def pw_hash(password: str, username: str) -> str:
    return hashlib.sha256((password + username[::-1] + SALT).encode()).hexdigest()[:16]


KIOSK = '''#!/usr/bin/env python3
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
'''


COMMON_PW = [
    "password", "123456", "12345678", "qwerty", "abc123", "monkey", "1234567",
    "letmein", "trustno1", "dragon", "baseball", "111111", "iloveyou", "master",
    "sunshine", "ashley", "bailey", "passw0rd", "shadow", "123123", "654321",
    "superman", "qazwsx", "michael", "football", "welcome", "jesus", "ninja",
    "mustang", "password1", "123456789", "adobe123", "admin", "princess",
    "azerty", "000000", "access", "flower", "555555", "passport", "batman",
    "soccer", "charlie", "donald", "hunter", "thomas", "robert", "batman1",
    "pepper", "ginger", "cookie", "coffee", "banana", "whatever", "zaq12wsx",
    "starwars", "nintendo", "pokemon", "maggie", "qwerty123", "killer", "george",
    "secret", "summer", "winter", "hello", "freedom", "chocolate", "camaro",
    "mercedes", "corvette", "harley", "yankees", "eagles", "cowboys", "lakers",
    "rangers", "celtic", "sniper", "matrix", "phantom", "ghost", "silver",
    "diamond", "platinum", "wallet", "deposit", "vault", "heist", "getaway",
    "police", "wanted", "trevor", "franklin", "lester", "lamar", "chop", "grove",
    "ballas", "vagos", "sandy", "paleto", "vespucci", "downtown", "vinewood",
]


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def build_db(path: Path) -> None:
    if path.exists():
        path.unlink()
    con = sqlite3.connect(path)
    con.executescript(
        """
        CREATE TABLE users(username TEXT PRIMARY KEY, pw_hash TEXT NOT NULL);
        CREATE TABLE vault(id INTEGER PRIMARY KEY, owner TEXT NOT NULL, secret TEXT NOT NULL);
        """
    )
    users = [
        ("admin", pw_hash(ADMIN_PW, "admin")),
        ("franklin", pw_hash("grove4life", "franklin")),
        ("michael", pw_hash("retirement_88", "michael")),
        ("lamar", pw_hash("ld_4life", "lamar")),
    ]
    con.executemany("INSERT INTO users(username, pw_hash) VALUES (?, ?)", users)
    vault = [
        ("franklin", _b64("locker-7734 cleared - no deposits on file")),
        ("michael", _b64("escrow slip 0082 - balance locked")),
        ("admin", _b64("master ledger - empty at 03:00")),
        ("FLEECA_CORE_7", _b64(FLAG)),
        ("trevor", _b64("impound hold 119 - pending seizure")),
    ]
    con.executemany("INSERT INTO vault(owner, secret) VALUES (?, ?)", vault)
    con.commit()
    con.close()


def write_wordlist(path: Path) -> None:
    assert ADMIN_PW in COMMON_PW
    rnd = random.Random(0x5EC0DEC0)
    words = list(COMMON_PW)
    extras = [f"{base}{n}{sfx}" for base in ("los", "santo", "fleeca", "bank", "crew")
              for n in range(3) for sfx in ("s", "77", "2026")]
    words.extend(extras)
    rnd.shuffle(words)
    path.write_text("\n".join(words) + "\n", encoding="utf-8")


def main() -> None:
    out = L.out_dir("M01")
    build_db(out / "fleeca.db")
    write_wordlist(out / "common_pw.txt")
    (out / "fleeca_kiosk.py").write_text(KIOSK, encoding="utf-8")
    for f in ("fleeca_kiosk.py", "fleeca.db", "common_pw.txt"):
        assert FLAG.encode() not in (out / f).read_bytes(), f"flag leaked into {f}"
    print(f"[M01] wrote fleeca.db, common_pw.txt, fleeca_kiosk.py -> {out}")
    print(f"[M01] admin password seeded (organizer only): {ADMIN_PW}")
    print(f"[M01] flag = {FLAG}")


if __name__ == "__main__":
    main()
