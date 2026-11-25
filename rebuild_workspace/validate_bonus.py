#!/usr/bin/env python3
"""BONUS WAVE validator (B01-B10). Private organizer tooling.

  1. Runs solve_bonus.py as a fresh subprocess and checks every mission prints
     PASS + the canonical flag.
  2. Anti-leak: no canonical bonus flag appears verbatim in any artefact, nor in
     any participant-served tree (challenges/, frontend/public, frontend/dist).
  3. Negative checks: the obvious/naive attack on each artefact dead-ends or
     yields a decoy, never the real flag.
"""
import base64
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
import gen_bonus as G
import solve_bonus as S

ROOT = L.ROOT
BONUS_IDS = [f"B{i:02d}" for i in range(1, 11)]


def _xor_repeat(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _art(cid):
    return L.out_dir(cid)


def main():
    here = Path(__file__).resolve().parent

    # 1. reference solver end to end -----------------------------------------
    r = subprocess.run([sys.executable, str(here / "solve_bonus.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, "solver exited %d\n%s" % (r.returncode, r.stderr)
    for cid in BONUS_IDS:
        assert f"[{cid}] PASS -> {L.FLAGS[cid]}" in r.stdout, f"{cid} missing from solver output"
    print(r.stdout.strip())

    # 2. anti-leak across artefacts + participant trees ----------------------
    roots = [ROOT / "challenges", ROOT / "frontend" / "public",
             ROOT / "frontend" / "dist", ROOT / "frontend" / "src"]
    leaks = []
    for cid in BONUS_IDS:
        for p in _art(cid).iterdir():
            if p.is_file() and L.FLAGS[cid].encode() in p.read_bytes():
                leaks.append(f"artefact:{p.name}")
    for base in roots:
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if not p.is_file():
                continue
            try:
                blob = p.read_bytes()
            except OSError:
                continue
            for cid in BONUS_IDS:
                if L.FLAGS[cid].encode() in blob:
                    leaks.append(str(p.relative_to(ROOT)))
    assert not leaks, f"bonus flag leaked: {sorted(set(leaks))}"

    # 3. negative checks -----------------------------------------------------
    # B01: without the game key the ciphertext is noise; the decoy is present.
    t = (_art("B01") / "dispatch_tape.txt").read_text(encoding="utf-8")
    assert G.DECOY_B01 in t
    assert L.FLAGS["B01"] not in S._xor_repeat(S._first_hex_long(t),
                                               b"\x00" * len(G.KEY_B01)).decode("latin-1")

    # B05: keying with the printed TOTAL or the item sum (instead of overcharge)
    # does NOT recover the flag.
    t = (_art("B05") / "receipt.txt").read_text(encoding="utf-8")
    blob = bytes.fromhex(re.search(r"OVERCHARGE_BLOB = ([0-9a-f]+)", t).group(1))
    for wrong in (5654, 4317, 0):
        assert _xor_repeat(blob, struct.pack("<I", wrong)).decode("latin-1") != L.FLAGS["B05"]

    # B06: a wrong wordlist entry never yields an FTA{ plaintext.
    cap = (_art("B06") / "handshake.hc22000").read_text(encoding="utf-8")
    salt = bytes.fromhex(re.search(r"SALT=([0-9a-f]+)", cap).group(1))
    cblob = bytes.fromhex(re.search(r"BLOB=([0-9a-f]+)", cap).group(1))
    for wrong in ("password", "fbi-surveillance-van", "surveillance-van-2025"):
        ks = hashlib.pbkdf2_hmac("sha256", wrong.encode(), salt, 60000, dklen=32)
        assert not _xor_repeat(cblob, ks).startswith(b"FTA{"), wrong

    # B07: vigenere-decrypting LINE 1 without undoing the rail fence dead-ends;
    # LINE 2 is a decoy that vigenere-decrypts to a fake flag.
    t = (_art("B07") / "lyrics_cipher.txt").read_text(encoding="utf-8")
    line1 = re.search(r"LINE 1 \(transposition over substitution\):\s*\n(\S+)", t).group(1)
    line2 = re.search(r"LINE 2 \(substitution only[^)]*\):\s*\n(\S+)", t).group(1)
    assert G.vig_dec(line1, "nevergonnagiveyouup") != L.FLAGS["B07"]
    assert G.vig_dec(line2, "nevergonnagiveyouup") == G.DECOY_B07

    # B08: the rendered body carries a decoy, not the flag.
    t = (_art("B08") / "raw_http_response.txt").read_text(encoding="utf-8")
    assert "FTA{404_fake_page}" in t and L.FLAGS["B08"] not in t

    # B09: keying with the LISTING ask price (4200) yields garbage.
    listing = json.loads((_art("B09") / "listing.json").read_text(encoding="utf-8"))
    blob = base64.b64decode(listing["COURIER_BLOB"])
    assert _xor_repeat(blob, struct.pack("<I", 4200)).decode("latin-1") != L.FLAGS["B09"]

    # B10: a single base64 decode does not yield the flag; decoys live in comments.
    t = (_art("B10") / "installer_script.sh").read_text(encoding="utf-8")
    b64 = re.search(r"echo '([A-Za-z0-9+/=]+)' \| base64 -d \| base64 -d", t).group(1)
    assert base64.b64decode(b64).decode("latin-1") != L.FLAGS["B10"]
    assert "FTA{just_use_arch_btw}" in t and "FTA{distrowatch_speedrun}" in t

    print("[bonus] VALIDATE OK — 10/10 solvers, no leak, naive attacks dead-end")


if __name__ == "__main__":
    main()
