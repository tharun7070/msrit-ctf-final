#!/usr/bin/env python3
"""E06 - Payphone Static (hardened DTMF/audio edition).

Produces two participant artifacts in challenges_rebuilt/EASY/E06:

    payphone.wav  16-bit PCM, 8000 Hz, mono, ~7.5 s. A payphone capture.
    EXCHANGE.txt  the courier debrief that documents how the line was used.

The flag is buried under four stacked layers and guarded by two traps:

  1. LSB STEGO TRAP : the least-significant bit of every PCM sample spells a
                      DECOY flag. A naive LSB sweep recovers the bait, never
                      the real value.
  2. CONCAT TRAP    : the audio carries THREE DTMF tone blocks split by
                      silence. Decoding the whole file and reading the digits
                      nose-to-tail is wrong: the leading six-digit HANDSHAKE
                      block is meaningless filler and must be dropped.

The genuine chain:

  S  = canonical flag string
  X  = zlib.compress(S)                       # deflate stream
  KW = a 3-letter lowercase word ("pier")     # fixed
  KS = SHA256(KW + b"payphone")               # 32-byte keystream, repeated
  C  = X XOR KS                               # ciphertext bytes
  D  = str(int.from_bytes(C, "big"))          # decimal digits -> PAYLOAD

  block A "handshake"        : 6 random digits, then a LONG (>=1.0 s) silence.
  block B "operational code" : KW on a custom keypad as (key,offset) digit
                               pairs (6 digits), then a MEDIUM (>=0.5 s) silence.
  block C "payload"          : the decimal digits of D.

The encryption key (KW) travels only as the middle DTMF block, read through
the keypad table printed in EXCHANGE.txt. The real flag never appears verbatim
in any artifact. All randomness is fixed-seed and byte-for-byte reproducible.
Private organizer tooling.
"""
import hashlib
import io
import random
import sys
import wave
import zlib
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

# ---------------------------------------------------------------------------
# constants
# ---------------------------------------------------------------------------
SEED = 0xE06A11
KW_WORD = "tap"                        # the 3-letter pad word (fixed)

SR = 8000                              # sample rate (Hz)
TONE_DUR = 0.040                       # 40 ms per DTMF tone
GAP_DUR = 0.012                        # 12 ms inter-digit gap
LONG_SIL = 1.00                        # >= 1.0 s  (block A -> block B)
MED_SIL = 0.50                         # >= 0.5 s  (block B -> block C)
AMP = 0.45
FADE = 0.004                           # 4 ms tone edge fade

DECOY_LSB_FLAG = "FTA{d34d_b34t_0n_th3_w1r3}"        # TRAP #1 bait (LSBs)
DECOY_NOTE_FLAG = "FTA{handshake_n0t_th3_r34l_0n3}"  # TRAP bait (printed)

# the keypad is 26 lowercase letters + 4 filler glyphs, permuted (10 keys x 3)
KP_EXTRA = "_#*0"

# standard DTMF frequency pairs (only the 0-9 digits are used here)
DTMF = {
    "1": (697, 1209), "2": (697, 1336), "3": (697, 1477),
    "4": (770, 1209), "5": (770, 1336), "6": (770, 1477),
    "7": (852, 1209), "8": (852, 1336), "9": (852, 1477),
    "0": (941, 1336),
}


# ---------------------------------------------------------------------------
# keypad
# ---------------------------------------------------------------------------
def build_keypad():
    """Seeded permutation of 26 letters + 4 filler glyphs -> 10 keys x 3."""
    rnd = random.Random(SEED ^ 0x4B57)
    chars = list("abcdefghijklmnopqrstuvwxyz") + list(KP_EXTRA)
    rnd.shuffle(chars)
    return "".join(chars)


def keypad_encode(word, keypad):
    """Encode a word as (key,offset) digit pairs, left to right."""
    out = []
    for ch in word:
        idx = keypad.index(ch)
        out.append(str(idx // 3))
        out.append(str(idx % 3))
    return "".join(out)


def keypad_table(keypad):
    lines = []
    for k in range(10):
        row = keypad[k * 3:k * 3 + 3]
        lines.append("  key %d : %s" % (k, "  ".join(row)))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# audio synthesis
# ---------------------------------------------------------------------------
def _tone(digit):
    f1, f2 = DTMF[digit]
    n = int(round(SR * TONE_DUR))
    t = np.arange(n) / SR
    s = (np.sin(2 * np.pi * f1 * t) + np.sin(2 * np.pi * f2 * t)) / 2.0
    env = np.ones(n)
    f = int(round(SR * FADE))
    if f > 0:
        ramp = np.linspace(0.0, 1.0, f)
        env[:f] = ramp
        env[-f:] = ramp[::-1]
    return s * AMP * env


def _sil(dur):
    return np.zeros(int(round(SR * dur)))


def build_signal(block_a, block_b, block_c):
    parts = []
    for d in block_a:                      # handshake (discard me)
        parts += [_tone(d), _sil(GAP_DUR)]
    parts.append(_sil(LONG_SIL))           # long double-interval
    for d in block_b:                      # operational code (keypad)
        parts += [_tone(d), _sil(GAP_DUR)]
    parts.append(_sil(MED_SIL))            # medium interval
    for d in block_c:                      # payload
        parts += [_tone(d), _sil(GAP_DUR)]
    return np.concatenate(parts)


def quantize(signal):
    return np.clip(np.round(signal * 32767.0), -32768, 32767).astype(np.int16)


def embed_lsb(pcm, text):
    """Write `text` ASCII MSB-first into the sample LSBs (TRAP #1)."""
    bits = "".join("{:08b}".format(ord(c)) for c in text)
    assert len(bits) <= len(pcm), "audio too short for the LSB payload"
    for i, b in enumerate(bits):
        pcm[i] = (int(pcm[i]) & ~1) | int(b)


def to_wav_bytes(pcm):
    bio = io.BytesIO()
    with wave.open(bio, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes(pcm.tobytes())
    return bio.getvalue()


# ---------------------------------------------------------------------------
# the courier debrief (TRAP #2 misdirection + the real keypad)
# ---------------------------------------------------------------------------
def build_exchange(keypad):
    return (
        "FLAG THEFT AUTO // EXCHANGE 06 - PAYPHONE RELAY DEBRIEF\n"
        "========================================================\n"
        "Channel  : disused payphone, Los Santos wire exchange\n"
        "Bearer   : DTMF touch-tone capture  (payphone.wav)\n"
        "Clearance: courier eyes only - do not retransmit\n"
        "\n"
        "WHAT WAS CAPTURED\n"
        "-----------------\n"
        "The line carried THREE tone blocks. A routine recorder drops the\n"
        "whole take as one stream and reads every digit nose-to-tail; that\n"
        "is exactly the mistake. Do NOT decode the file as a single number.\n"
        "\n"
        "  1) HANDSHAKE  - the FIRST block (six digits). It is only a dial\n"
        "                  confirmation; it carries no traffic. DISCARD it.\n"
        "  2) The LONG DOUBLE-INTERVAL after the handshake separates the\n"
        "     filler from the real signal. The block that FOLLOWS it is the\n"
        "     genuine OPERATIONAL CODE (six digits, read on the keypad).\n"
        "  3) After the SHORTER interval comes the PAYLOAD: one long\n"
        "     decimal number that must be turned back into raw bytes.\n"
        "\n"
        "KEYPAD (read the six digits as (key,offset) PAIRS)\n"
        "--------------------------------------------------\n"
        + keypad_table(keypad) + "\n"
        "\n"
        "Read the six operational digits left to right as three pairs\n"
        "(key,offset): each pair selects ONE glyph - the glyph in that row\n"
        "at that column (offset 0 = first column). The three glyphs spell\n"
        "the WORD that keys the payload. (Filler glyphs appear on the pad;\n"
        "the traffic word uses letters only.)\n"
        "\n"
        "PAYLOAD DECODE\n"
        "--------------\n"
        "Take the payload block as a single decimal integer. Convert it to\n"
        "big-endian bytes. XOR every byte with the byte-stream\n"
        "SHA256(WORD + \"payphone\") repeated to the required length. The\n"
        "result is a zlib stream; inflate it to recover the phrase.\n"
        "\n"
        "CONFIRMED COURIER PHRASE (bait - do not submit)\n"
        "-----------------------------------------------\n"
        "confirmed courier phrase: " + DECOY_NOTE_FLAG + "\n"
    )


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    flag = L.FLAGS["E06"]
    rnd = random.Random(SEED)

    # --- the real chain -----------------------------------------------------
    X = zlib.compress(flag.encode())
    KS = hashlib.sha256(KW_WORD.encode() + b"payphone").digest()
    C = bytes(x ^ KS[i % 32] for i, x in enumerate(X))
    assert C[0] != 0, "leading zero would make the decimal payload ambiguous"
    payload = str(int.from_bytes(C, "big"))

    keypad = build_keypad()
    block_b = keypad_encode(KW_WORD, keypad)
    block_a = "".join(str(rnd.randrange(10)) for _ in range(6))
    block_c = payload
    assert len(block_b) == 6 and len(block_a) == 6

    # --- render the audio ---------------------------------------------------
    signal = build_signal(block_a, block_b, block_c)
    pcm = quantize(signal)
    embed_lsb(pcm, DECOY_LSB_FLAG)
    wav_bytes = to_wav_bytes(pcm)
    L.write_bytes("E06", "payphone.wav", wav_bytes)
    print("wrote payphone.wav (%d bytes, %.2f s, %d samples)"
          % (len(wav_bytes), len(pcm) / SR, len(pcm)))

    text = build_exchange(keypad)
    p = L.write_text("E06", "EXCHANGE.txt", text)
    print("wrote EXCHANGE.txt (%d bytes)" % p.stat().st_size)

    # --- verify -------------------------------------------------------------
    dur = len(pcm) / SR
    assert 6.0 <= dur <= 8.5, "duration out of the intended 6-8 s window: %.2f" % dur
    assert flag.encode() not in wav_bytes, "real flag leaked into the wav!"
    assert flag not in text, "real flag leaked into EXCHANGE.txt!"
    # the decoy must be trivially recoverable from the raw LSBs (TRAP #1)
    bits = "".join(str(int(v) & 1) for v in pcm)
    recovered = "".join(chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits) - 7, 8))
    assert DECOY_LSB_FLAG in recovered, "LSB decoy not recoverable"
    assert DECOY_NOTE_FLAG in text and DECOY_NOTE_FLAG != flag
    print("[E06] layers: DTMF(3 blocks) + zlib + SHA256-XOR | decoy LSB + handshake trap")
    print("[E06] keypad word=%r  blockB(pairs)=%s  payload=%d digits"
          % (KW_WORD, block_b, len(block_c)))


if __name__ == "__main__":
    main()
