#!/usr/bin/env python3
"""BONUS WAVE reference solver (B01-B10). Private organizer tooling.

Inverts every bonus artefact exactly the way a participant would and asserts the
recovered value equals the canonical flag. Prints one ``[Bxx] PASS -> <flag>``
line per mission. Imports the shared game keys from gen_bonus so the two stay in
lock-step.
"""
import base64
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
import gen_bonus as G


def _xor_repeat(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _first_hex_long(text: str) -> bytes:
    """Collect the wrapped hex block that follows the 'CIPHERTEXT (hex):' marker."""
    marker = "CIPHERTEXT (hex):"
    region = text[text.index(marker) + len(marker):]
    lines = []
    for line in region.splitlines():
        s = line.strip()
        if re.fullmatch(r"[0-9a-fA-F]+", s):
            lines.append(s)
        elif lines:
            break
    assert lines, "no hex block found"
    return bytes.fromhex("".join(lines))


def solve_b01():
    text = (L.out_dir("B01") / "dispatch_tape.txt").read_text(encoding="utf-8")
    flag = _xor_repeat(_first_hex_long(text), G.KEY_B01.encode()).decode()
    assert flag == L.FLAGS["B01"], flag
    print("[B01] PASS ->", flag)
    return flag


def solve_b02():
    text = (L.out_dir("B02") / "reflex_log.txt").read_text(encoding="utf-8")
    flag = _xor_repeat(_first_hex_long(text), G.KEY_B02.encode()).decode()
    assert flag == L.FLAGS["B02"], flag
    print("[B02] PASS ->", flag)
    return flag


def solve_b03():
    text = (L.out_dir("B03") / "starship_manifest.txt").read_text(encoding="utf-8")
    flag = _xor_repeat(_first_hex_long(text), G.KEY_B03.encode()).decode()
    assert flag == L.FLAGS["B03"], flag
    print("[B03] PASS ->", flag)
    return flag


def solve_b04():
    doc = json.loads((L.out_dir("B04") / "achievements.json").read_text(encoding="utf-8"))
    blob = bytes.fromhex(doc["masked_payload_hex"])
    flag = _xor_repeat(blob, G.KEY_B04.encode()).decode()
    assert flag == L.FLAGS["B04"], flag
    print("[B04] PASS ->", flag)
    return flag


def solve_b05():
    text = (L.out_dir("B05") / "receipt.txt").read_text(encoding="utf-8")
    item_sum = sum(int(q) * int(p) for q, p in re.findall(r"(\d+)\s*x\s+(\d+)", text))
    printed = int(re.search(r"SUBTOTAL \(printed\)\s+(\d+)", text).group(1))
    overcharge = printed - item_sum
    blob = bytes.fromhex(re.search(r"OVERCHARGE_BLOB = ([0-9a-f]+)", text).group(1))
    flag = _xor_repeat(blob, struct.pack("<I", overcharge)).decode()
    assert flag == L.FLAGS["B05"], flag
    print("[B05] PASS ->", flag)
    return flag


def solve_b06():
    out = L.out_dir("B06")
    cap = (out / "handshake.hc22000").read_text(encoding="utf-8")
    salt = bytes.fromhex(re.search(r"SALT=([0-9a-f]+)", cap).group(1))
    blob = bytes.fromhex(re.search(r"BLOB=([0-9a-f]+)", cap).group(1))
    words = [w.strip() for w in (out / "wordlist.txt").read_text(encoding="utf-8").splitlines() if w.strip()]
    for pw in words:
        ks = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 60000, dklen=32)
        cand = _xor_repeat(blob, ks)
        if cand.startswith(b"FTA{"):
            flag = cand.decode()
            assert flag == L.FLAGS["B06"], flag
            print("[B06] PASS ->", flag)
            return flag
    raise AssertionError("no passphrase in the wordlist yielded the flag")


def solve_b07():
    text = (L.out_dir("B07") / "lyrics_cipher.txt").read_text(encoding="utf-8")
    m = re.search(r"LINE 1 \(transposition over substitution\):\s*\n(\S+)", text)
    assert m, "LINE 1 not found"
    unwound = G.rail_decode(m.group(1), 5)
    flag = G.vig_dec(unwound, "nevergonnagiveyouup")
    assert flag == L.FLAGS["B07"], flag
    print("[B07] PASS ->", flag)
    return flag


def solve_b08():
    text = (L.out_dir("B08") / "raw_http_response.txt").read_text(encoding="utf-8")
    route = re.search(r"X-Courier-Route:\s*(\S+)", text).group(1)
    flag = base64.b64decode(base64.b64decode(route)).decode()
    assert flag == L.FLAGS["B08"], flag
    print("[B08] PASS ->", flag)
    return flag


def solve_b09():
    out = L.out_dir("B09")
    listing = json.loads((out / "listing.json").read_text(encoding="utf-8"))
    blob = base64.b64decode(listing["COURIER_BLOB"])
    chat = (out / "chat_log.txt").read_text(encoding="utf-8")
    price = int(re.search(r"final price:\s*\$(\d+)", chat).group(1))
    flag = _xor_repeat(blob, struct.pack("<I", price)).decode()
    assert flag == L.FLAGS["B09"], flag
    print("[B09] PASS ->", flag)
    return flag


def solve_b10():
    text = (L.out_dir("B10") / "installer_script.sh").read_text(encoding="utf-8")
    b64 = re.search(r"echo '([A-Za-z0-9+/=]+)' \| base64 -d \| base64 -d", text).group(1)
    flag = base64.b64decode(base64.b64decode(b64)).decode()
    assert flag == L.FLAGS["B10"], flag
    print("[B10] PASS ->", flag)
    return flag


SOLVERS = [solve_b01, solve_b02, solve_b03, solve_b04, solve_b05,
           solve_b06, solve_b07, solve_b08, solve_b09, solve_b10]


def main():
    for fn in SOLVERS:
        fn()
    print(">>> ALL 10 BONUS SOLVERS PASSED - $250 <<<")


if __name__ == "__main__":
    main()
