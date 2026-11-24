#!/usr/bin/env python3
"""M01 - Fleeca Vault Glitch. Generator (private organizer tooling).

Produces the participant artifacts in L.out_dir("M01"):
  - fleeca_kiosk.py : vulnerable offline terminal. The bug is a TWO-STAGE
                      stored (second-order) injection: register stores a
                      username, `sync` stores a *derived* alias, and `load`
                      interpolates only that alias raw into the vault query.
                      Authentication uses a DB-bound custom hash and an
                      HMAC session token sealed with a DB-only key.
  - fleeca.db       : sqlite snapshot. Holds per-user salts, the server
                      pepper, the session key and two secret tables. The real
                      flag lives in the `escrow` table, base64-encoded.
  - common_pw.txt   : leaked wordlist containing the honeypot admin password.

Layers stacked (all required to reach the flag):
  L1  two-stage stored injection + a custom "scrubber" with a deliberate
      bypass (it doubles quotes but the doubling is undone on read; it drops
      the `--` line-comment token but never the `/*...*/` block form).
  L2  non-trivial hash: trunc(sha256(tag|per_user_salt|pw|user[::-1]|pepper))
      where the salt is per-user and the pepper lives in the config table.
      Cracking the password *requires* reading fleeca.db.
  L3  session gate: login issues HMAC(secret_key, user|nonce); load only
      unmasks receipts for a session whose HMAC verifies. secret_key is
      recoverable only from the config table.
  L4  decoys: a honeypot `admin` account (crackable, but its vault entry is a
      plausible WRONG flag) and a decoy table (`vault`, the "shallower" union
      target) plus a second decoy table (`receipts`) full of fake flags. The
      real ledger name is only advertised by config.core_ledger.

The raw flag string is NEVER written to any participant file: the real ledger
stores it base64-encoded and the kiosk de-escrows it on display at runtime only.
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
HASH_TAG = "fleeca-h2"

# Honeypot account: obvious name, crackable password (present in the wordlist),
# but its vault entry is a plausible WRONG flag.
HONEYPOT_USER = "admin"
HONEYPOT_PW = "sunshine"

# Real operator account: its password is NOT in the wordlist, so the only way
# to its ledger is the injection -- not credential cracking.
CORE_USER = "fleeca_core"
CORE_PW = "V4ult-C0re-0perator-2026"

FAKE_ADMIN = "FTA{adm1n_p4n3l_n0t_th3_fl4g}"
FAKE_LEDGER = "FTA{cl0s3_fl33c4_c0r3_l3dg3r}"
FAKE_RECEIPT = "FTA{r3c31pt_d3c0y_r0w_7}"

# Deterministic, DB-bound secrets (no RNG needed so fleeca.db is byte-stable).
PEPPER = "pep-" + hashlib.sha1(b"fleeca-pepper-v3").hexdigest()[:24]
SESSION_KEY = hashlib.sha256(b"fleeca-kiosk-session-v3").hexdigest()  # 32 bytes hex
assert len(SESSION_KEY) == 64


def _salt(name: str) -> str:
    """Deterministic per-user salt (generator-side); register() makes its own."""
    return hashlib.sha256(f"fleeca-salt|{name}".encode()).hexdigest()[:16]


def _hash(password: str, username: str, salt: str, pepper: str) -> str:
    material = f"{HASH_TAG}|{salt}|{password}|{username[::-1]}|{pepper}"
    return hashlib.sha256(material.encode()).hexdigest()[:20]


def pw_hash(password: str, username: str) -> str:
    """Convenience wrapper used only against the seeded accounts."""
    return _hash(password, username, _salt(username), PEPPER)


KIOSK = '''#!/usr/bin/env python3
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
    alias = _scrub(row[0])
    con.execute(
        "INSERT INTO profiles(username, alias, updated) VALUES (?, ?, ?) "
        "ON CONFLICT(username) DO UPDATE SET alias = excluded.alias, updated = excluded.updated",
        (row[0], alias, 1),
    )
    con.commit()
    con.close()
    print(f"sync: alias registry updated for {username!r}")
    return 0


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
    # Restore the escaped display text before the legacy vault lookup.
    alias = prow[0].replace("''", "'")
    query = f"SELECT owner, secret FROM vault WHERE owner = '{alias}'"
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
        CREATE TABLE users(
            username TEXT PRIMARY KEY,
            pw_hash TEXT NOT NULL,
            pw_salt TEXT NOT NULL,
            role TEXT NOT NULL
        );
        CREATE TABLE profiles(
            username TEXT PRIMARY KEY,
            alias TEXT NOT NULL,
            updated INTEGER NOT NULL
        );
        CREATE TABLE config(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE vault(id INTEGER PRIMARY KEY, owner TEXT NOT NULL, secret TEXT NOT NULL);
        CREATE TABLE receipts(id INTEGER PRIMARY KEY, owner TEXT NOT NULL, secret TEXT NOT NULL);
        CREATE TABLE escrow(id INTEGER PRIMARY KEY, owner TEXT NOT NULL, secret TEXT NOT NULL);
        """
    )
    accounts = [
        (HONEYPOT_USER, HONEYPOT_PW, "auditor"),
        (CORE_USER, CORE_PW, "core"),
        ("franklin", "grove4life", "teller"),
        ("michael", "retirement_88", "teller"),
        ("lamar", "ld_4life", "teller"),
    ]
    con.executemany(
        "INSERT INTO users(username, pw_hash, pw_salt, role) VALUES (?, ?, ?, ?)",
        [(u, pw_hash(p, u), _salt(u), r) for u, p, r in accounts],
    )
    con.executemany(
        "INSERT INTO config(key, value) VALUES (?, ?)",
        [
            ("hash_tag", HASH_TAG),
            ("server_pepper", PEPPER),
            ("session_key", SESSION_KEY),
            ("legacy_ledger", "vault"),
            ("core_ledger", "escrow"),
        ],
    )
    # Decoy table the kiosk's own query already targets ("shallower" union).
    con.executemany(
        "INSERT INTO vault(owner, secret) VALUES (?, ?)",
        [
            (HONEYPOT_USER, _b64(FAKE_ADMIN)),
            ("franklin", _b64("locker-7734 cleared - no deposits on file")),
            ("michael", _b64("escrow slip 0082 - balance locked")),
            ("trevor", _b64("impound hold 119 - pending seizure")),
            ("lamar", _b64("no holdings on record")),
            ("escrow_core", _b64(FAKE_LEDGER)),
        ],
    )
    # Second decoy table, full of fake flags.
    con.executemany(
        "INSERT INTO receipts(owner, secret) VALUES (?, ?)",
        [
            ("auditor", _b64(FAKE_RECEIPT)),
            ("teller", _b64("till 3 reconciled")),
        ],
    )
    # Real ledger. Only advertised via config.core_ledger.
    con.executemany(
        "INSERT INTO escrow(owner, secret) VALUES (?, ?)",
        [
            ("FLEECA_CORE_7", _b64(FLAG)),
            ("maintenance", _b64("scheduled sweep 04:00")),
            ("FLEECA_CORE_1", _b64("cold storage segment sealed")),
        ],
    )
    con.commit()
    con.close()


def write_wordlist(path: Path) -> None:
    assert HONEYPOT_PW in COMMON_PW
    assert CORE_PW not in COMMON_PW
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
    print(f"[M01] honeypot account seeded (organizer only): {HONEYPOT_USER}/{HONEYPOT_PW}")
    print(f"[M01] flag = {FLAG}")


if __name__ == "__main__":
    main()
