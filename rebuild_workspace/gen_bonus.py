#!/usr/bin/env python3
"""BONUS WAVE generators (B01-B10). Private organizer tooling.

Produces every participant artefact for the 10 bonus challenges into
``challenges_rebuilt/BONUS/<CID>/``. All randomness is fixed, so the build is
byte-for-byte reproducible. The real flag never appears verbatim in any file;
each artefact carries the flag masked with a key the participant must recover
(from an on-site mini-game for B01-B04, or from analysis for B05-B10).

B01-B04 : browser mini-games reveal a 16-byte ASCII key; artifact = hex(flag XOR key)
B05     : receipt arithmetic -> overcharge (1337) keys a 4-byte-LE-repeated XOR
B06     : weak passphrase -> PBKDF2-HMAC-SHA256 keystream over a blob
B07     : rail-fence(width 5) over Vigenere(key='nevergonnagiveyouup')
B08     : raw HTTP response; header carries base64(base64(flag))
B09     : seller chat price (3699) keys a 4-byte-LE-repeated XOR of a b64 blob
B10     : shell script; real payload is double base64 (decoys in comments)
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

# 16-byte ASCII game keys (revealed only by winning the on-site mini-games).
KEY_B01 = "5IM0N-D15P4TCH-K"
KEY_B02 = "R3FL3X-W1ND0W-26"
KEY_B03 = "WARP-C0RE-K3Y-26"
KEY_B04 = "T0UCH3D-GR4SS-26"

DECOY_B01 = "FTA{n0t_th3_r34l_s3qu3nc3}"
DECOY_B07 = "FTA{n3v3r_g0nn4_l3t_y0u_d0wn}"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def xor_repeat(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def xor_le32(data: bytes, value: int) -> bytes:
    import struct
    key = struct.pack("<I", value)
    return xor_repeat(data, key)


def hex_block(data: bytes, width: int = 64) -> str:
    h = data.hex()
    return "\n".join(h[i:i + width] for i in range(0, len(h), width))


# --- rail fence (B07) -------------------------------------------------------
def rail_encode(text: str, rails: int) -> str:
    if rails <= 1:
        return text
    rows = [[] for _ in range(rails)]
    rail, direction = 0, 1
    for ch in text:
        rows[rail].append(ch)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    return "".join("".join(r) for r in rows)


def rail_decode(text: str, rails: int) -> str:
    if rails <= 1:
        return text
    n = len(text)
    pattern, rail, direction = [], 0, 1
    for _ in range(n):
        pattern.append(rail)
        if rail == 0:
            direction = 1
        elif rail == rails - 1:
            direction = -1
        rail += direction
    counts = [pattern.count(r) for r in range(rails)]
    rows, idx = [], 0
    for r in range(rails):
        rows.append(list(text[idx:idx + counts[r]]))
        idx += counts[r]
    iters = [0] * rails
    out = []
    for r in pattern:
        out.append(rows[r][iters[r]])
        iters[r] += 1
    return "".join(out)


# --- vigenere (B07) ---------------------------------------------------------
def vig_enc(text: str, key: str) -> str:
    ks = [ord(c) - 97 for c in key.lower() if c.isalpha()]
    out, ki = [], 0
    for ch in text:
        if ch.isalpha():
            base = 97 if ch.islower() else 65
            out.append(chr((ord(ch) - base + ks[ki % len(ks)]) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


def vig_dec(text: str, key: str) -> str:
    ks = [ord(c) - 97 for c in key.lower() if c.isalpha()]
    out, ki = [], 0
    for ch in text:
        if ch.isalpha():
            base = 97 if ch.islower() else 65
            out.append(chr((ord(ch) - base - ks[ki % len(ks)]) % 26 + base))
            ki += 1
        else:
            out.append(ch)
    return "".join(out)


# ---------------------------------------------------------------------------
# B01-B04 : 16-byte-keyed XOR tape
# ---------------------------------------------------------------------------
def gen_tape(cid, filename, key, header_lines, decoy=None):
    flag = L.FLAGS[cid].encode()
    blob = xor_repeat(flag, key.encode())
    parts = list(header_lines) + ["", "CIPHERTEXT (hex):", hex_block(blob), ""]
    if decoy:
        parts += ["-- scratch note --", decoy, ""]
    text = "\n".join(parts)
    L.write_text(cid, filename, text)
    assert L.FLAGS[cid] not in text
    return blob


def gen_b01():
    gen_tape(
        "B01", "dispatch_tape.txt", KEY_B01,
        ["DISPATCH TAPE // raw XOR-masked packet log",
         "The desk key is 16 ASCII bytes. Win the Simon dispatch game on the",
         "event site to make the desk print it, then XOR it across these bytes."],
        decoy=DECOY_B01)


def gen_b02():
    gen_tape(
        "B02", "reflex_log.txt", KEY_B02,
        ["ALARM RIG LOG // XOR-masked event trace",
         "The rig prints a 16-byte key only on a clean, fast hit in the on-site",
         "reflex game. XOR the repeating key across these bytes."])


def gen_b03():
    gen_tape(
        "B03", "starship_manifest.txt", KEY_B03,
        ["STARSHIP MANIFEST // XOR-masked cargo list",
         "Use the on-site bridge terminal to unlock the log; it prints the",
         "16-byte key. XOR the repeating key across these bytes."])


def gen_b04():
    flag = L.FLAGS["B04"].encode()
    blob = xor_repeat(flag, KEY_B04.encode())
    doc = {
        "profile": "grasses_untouched",
        "note": "The launcher withholds the key until you leave it alone. Any input resets it.",
        "achievements": [
            {"id": "first_login", "unlocked": True},
            {"id": "opened_the_app", "unlocked": True},
            {"id": "t0uch_gr4ss_pls", "unlocked": False, "hint": "not this one"},
            {"id": "go_outside", "unlocked": False, "hint": "closer"},
            {"id": "leave_launcher_idle_30s", "unlocked": False},
        ],
        "payload_mask": "the achievement id the launcher prints on unlock, XOR, repeated",
        "masked_payload_hex": blob.hex(),
    }
    text = json.dumps(doc, indent=2) + "\n"
    L.write_text("B04", "achievements.json", text)
    assert L.FLAGS["B04"] not in text


# ---------------------------------------------------------------------------
# B05 : Niko's pizza receipt (overcharge arithmetic)
# ---------------------------------------------------------------------------
def gen_b05():
    items = [(2, 1499, "Pepperoni Alpaca"), (1, 899, "Garlic Knots (dozen)"),
             (3, 99, "Cheesy Crust Upgrade"), (1, 123, "Delivery (Sandy Shores)")]
    item_sum = sum(q * p for q, p, _ in items)
    overcharge = 1337
    printed_total = item_sum + overcharge
    lines = ["PIZZA THIS // 1399 Route 68, Sandy Shores",
             "NIKO  TABLE 7   ORDER #4317", "=" * 44]
    for q, p, name in items:
        lines.append(f"  {q} x {p:>5}  {name:<24} {q * p:>6}")
    lines += ["-" * 44,
              f"  SUBTOTAL (printed)              {printed_total:>6}",
              "",
              "  Service fee and 'convenience' charge folded into the line above.",
              "  Niko swears the total is wrong by a whole number of cents.",
              "  The stapled blob is masked with that overcharge.",
              "",
              f"OVERCHARGE_BLOB = {xor_le32(L.FLAGS['B05'].encode(), overcharge).hex()}",
              ""]
    text = "\n".join(lines)
    L.write_text("B05", "receipt.txt", text)
    assert L.FLAGS["B05"] not in text
    assert item_sum == 4317 and printed_total == 5654  # keep the answer key honest


# ---------------------------------------------------------------------------
# B06 : Wi-Fi named 'FBI Surveillance Van'
# ---------------------------------------------------------------------------
def gen_b06():
    passphrase = "surveillance-van-2026"
    salt = b"LSVan-Salt-2026!"
    ks = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 60000, dklen=32)
    blob = xor_repeat(L.FLAGS["B06"].encode(), ks)
    cap = "\n".join([
        "WPA*02*LSVAN-HANDSHAKE-2026",
        "SSID=FBI Surveillance Van",
        f"SALT={salt.hex()}",
        f"BLOB={blob.hex()}",
        "# toy capture: one salt + one blob, no real 4-way handshake",
        "",
    ])
    L.write_text("B06", "handshake.hc22000", cap)
    assert L.FLAGS["B06"] not in cap

    wordlist = [
        "password", "12345678", "letmein", "admin", "fbi-surveillance-van",
        "SurveillanceVan", "surveillance-van-2025", "surveillance-van-2026",
        "notthefbi", "trustno1", "alsonotthefbi", "01189998819991197253",
        "guest-wifi", "freewifi", "vanlife",
    ]
    L.write_text("B06", "wordlist.txt", "\n".join(wordlist) + "\n")


# ---------------------------------------------------------------------------
# B07 : Rick Roll Protocol
# ---------------------------------------------------------------------------
def gen_b07():
    key = "nevergonnagiveyouup"
    ct = rail_encode(vig_enc(L.FLAGS["B07"], key), 5)
    decoy = vig_enc(DECOY_B07, key)
    text = "\n".join([
        "RICK ROLL PROTOCOL // intercepted courier love letter",
        "=" * 52,
        "Two layers, in the wrong order you will serenade yourself.",
        "",
        "LINE 1 (transposition over substitution):",
        ct,
        "",
        "LINE 2 (substitution only - the courier got lazy):",
        decoy,
        "",
    ])
    L.write_text("B07", "lyrics_cipher.txt", text)
    assert L.FLAGS["B07"] not in text


# ---------------------------------------------------------------------------
# B08 : 404 Flag Not Found
# ---------------------------------------------------------------------------
def gen_b08():
    payload = base64.b64encode(base64.b64encode(L.FLAGS["B08"].encode())).decode()
    body = ("<html><head><title>404</title></head><body>"
            "<h1>404 Not Found</h1><p>There is no flag here.</p>"
            f"<pre>flag = FTA{{404_fake_page}}</pre></body></html>")
    response = "\r\n".join([
        "HTTP/1.1 404 Not Found",
        "Server: nginx/1.25.3",
        "Date: Fri, 20 Nov 2026 09:41:00 GMT",
        "Content-Type: text/html; charset=utf-8",
        f"X-Courier-Route: {payload}",
        "X-Powered-By: disappointment",
        f"Content-Length: {len(body)}",
        "Connection: close",
        "",
        body, "",
    ])
    L.write_text("B08", "raw_http_response.txt", response)
    assert L.FLAGS["B08"] not in response


# ---------------------------------------------------------------------------
# B09 : Facebook Marketplace Rugpull
# ---------------------------------------------------------------------------
def gen_b09():
    price = 3699
    blob = xor_le32(L.FLAGS["B09"].encode(), price)
    listing = {
        "platform": "Marketplace",
        "title": "CHEAP CAR - no lowballers - I know what I have",
        "ask_price": 4200,
        "condition": "runs and drives (allegedly)",
        "description": "Serious buyers only. Do NOT waste my time.",
        "COURIER_BLOB": base64.b64encode(blob).decode(),
    }
    listing_text = json.dumps(listing, indent=2) + "\n"
    L.write_text("B09", "listing.json", listing_text)
    assert L.FLAGS["B09"] not in listing_text

    chat = "\n".join([
        "[buyer] is it still available?",
        "[seller] yes. $4200 firm, no lowballers.",
        "[buyer] how about $3000",
        "[seller] lol no",
        "[buyer] $3699 final",
        "[seller] final price: $3699. deal. bring cash, no receipts.",
        "[buyer] ok sending the courier blob now",
        "[seller] if the amount in the blob does not match, it decodes to garbage. just saying",
        "",
    ])
    L.write_text("B09", "chat_log.txt", chat)
    assert L.FLAGS["B09"] not in chat


# ---------------------------------------------------------------------------
# B10 : Grand Theft Alpaca: Install Linux
# ---------------------------------------------------------------------------
def gen_b10():
    payload = base64.b64encode(base64.b64encode(L.FLAGS["B10"].encode())).decode()
    script = "\n".join([
        "#!/bin/sh",
        "# grand-theft-alpaca-installer.sh",
        "# 90% jokes, 10% payload. Run it in your head, not on your machine.",
        "set -e",
        "",
        "echo '[+] alpaca detected...'",
        "echo '[+] compiling kernel (this is a joke, it takes 4 hours)'",
        "# if you are reading this you are already overthinking it",
        "# earlier revision leaked a fake flag: FTA{just_use_arch_btw}",
        "echo 'rm -rf / -- no-preserve-root   # <-- definitely do not run this'",
        "alias apt='sudo apt'   # trust me bro",
        "",
        "# --- the actual payload lives here; everything above is noise ---",
        f"echo '{payload}' | base64 -d | base64 -d",
        "",
        "echo '[+] done. now go touch grass.'",
        "",
        "# decoy, do not submit: FTA{distrowatch_speedrun}",
        "",
    ])
    L.write_text("B10", "installer_script.sh", script)
    assert L.FLAGS["B10"] not in script


# ---------------------------------------------------------------------------
def main():
    gen_b01(); gen_b02(); gen_b03(); gen_b04()
    gen_b05(); gen_b06(); gen_b07(); gen_b08(); gen_b09(); gen_b10()
    print("[bonus] generated B01-B10 artefacts under challenges_rebuilt/BONUS/")


if __name__ == "__main__":
    main()
