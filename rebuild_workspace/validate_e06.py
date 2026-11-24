#!/usr/bin/env python3
"""E06 - Payphone Static. Validator (private).

  1. Runs solve_e06.py as a fresh subprocess and checks it prints PASS + the
     canonical flag.
  2. NEGATIVE #1 (LSB trap)   : a naive LSB sweep of the wav recovers only the
     decoy flag - never the real one.
  3. NEGATIVE #2 (concat trap): decoding the whole file and reading every DTMF
     digit nose-to-tail (handshake included) is the wrong digit string and does
     NOT yield the real flag.
  4. NEGATIVE #3 (handshake)  : keying the payload with the handshake block
     instead of the operational code does NOT yield the real flag.
  5. Anti-leak: the real flag string appears in no artifact; the printed decoy
     line in EXCHANGE.txt is a different string.
"""
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
import solve_e06 as S

REAL = L.FLAGS["E06"]


def naive_lsb_text(samples):
    """The obvious-but-wrong attack: read the LSB of every sample, MSB-first."""
    bits = "".join(str(int(v) & 1) for v in samples)
    return "".join(chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits) - 7, 8))


def main():
    here = Path(__file__).resolve().parent

    # 1. reference solver end to end -----------------------------------------
    r = subprocess.run([sys.executable, str(here / "solve_e06.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, "solver exited %d\n%s" % (r.returncode, r.stderr)
    expected = "[E06] PASS -> " + REAL
    assert expected in r.stdout, "solver stdout: %r" % r.stdout
    print(r.stdout.strip())

    out = L.out_dir("E06")
    wav_path = out / "payphone.wav"
    txt_path = out / "EXCHANGE.txt"
    samples, sr = S.read_pcm(wav_path)
    text = txt_path.read_text(encoding="utf-8")

    # anti-leak ---------------------------------------------------------------
    assert REAL.encode() not in wav_path.read_bytes(), "real flag leaked in wav"
    assert REAL not in text, "real flag leaked in EXCHANGE.txt"

    # 2. NEGATIVE #1: naive LSB sweep -> decoy, not the real flag -------------
    lsb_text = naive_lsb_text(samples)
    decoys = re.findall(r"FTA\{[a-z0-9_]+\}", lsb_text)
    assert decoys, "expected a decoy flag in the LSBs"
    assert all(d != REAL for d in decoys), "LSB sweep yielded the real flag!"
    decoy_lsb = decoys[0]

    # 3. NEGATIVE #2: whole-file DTMF concat (handshake included) is wrong ----
    blocks = S.decode_blocks(samples, sr)
    assert len(blocks) == 3, blocks
    naive_digits = "".join(blocks)
    assert naive_digits != blocks[2], "handshake did not perturb the naive decode"
    keypad = S.load_keypad(text)
    word = S.keypad_decode(blocks[1], keypad)
    naive_flag = S.payload_word_to_flag(naive_digits, word)
    assert naive_flag != REAL, "naive concatenation produced the real flag!"

    # 4. NEGATIVE #3: keying the payload with the handshake block dead-ends ---
    wrong_word = S.keypad_decode(blocks[0], keypad)
    wrong_flag = S.payload_word_to_flag(blocks[2], wrong_word)
    assert wrong_flag != REAL, "handshake block keyed the real flag!"

    # 5. printed decoy is a different string ----------------------------------
    m = re.search(r"confirmed courier phrase:\s*(FTA\{[^}]+\})", text)
    assert m, "printed decoy line missing"
    assert m.group(1) != REAL, "printed decoy equals the real flag!"

    print("[E06] VALIDATE OK (lsb_decoy=%r, naive_len=%d, handshake_key=%r)"
          % (decoy_lsb, len(naive_digits), wrong_word))


if __name__ == "__main__":
    main()
