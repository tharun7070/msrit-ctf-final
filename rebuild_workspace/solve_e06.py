#!/usr/bin/env python3
"""E06 reference solver (hardened).

Inverts `payphone.wav` + `EXCHANGE.txt`:

  1. read the PCM and find the DTMF tone blocks separated by silence;
  2. DROP the leading handshake block (TRAP #2):
        block A (6 digits, filler) | block B (6 digits, keypad) | block C (payload)
  3. read the keypad table from EXCHANGE.txt and decode block B into the WORD;
  4. decimal(payload) -> big-endian bytes -> XOR SHA256(WORD+"payphone")
     keystream -> zlib.decompress -> flag.

The LSB of every sample spells a decoy flag (TRAP #1); this solver never reads
the LSBs.
"""
import hashlib
import re
import sys
import wave
import zlib
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

LOW = [697, 770, 852, 941]
HIGH = [1209, 1336, 1477]
DTMF_MAP = {
    (697, 1209): "1", (697, 1336): "2", (697, 1477): "3",
    (770, 1209): "4", (770, 1336): "5", (770, 1477): "6",
    (852, 1209): "7", (852, 1336): "8", (852, 1477): "9",
    (941, 1209): "*", (941, 1336): "0", (941, 1477): "#",
}
MERGE_GAP = 0.25   # seconds of silence that separates two DTMF blocks


def read_pcm(path):
    """Return (int32 sample array, sample rate)."""
    with wave.open(str(path), "rb") as w:
        sr = w.getframerate()
        n = w.getnframes()
        data = w.readframes(n)
    return np.frombuffer(data, dtype="<i2").astype(np.int32), sr


def digit_segments(samples, sr):
    """Return [(start,end)] sample spans, one per DTMF tone."""
    a = np.abs(samples)
    win = max(1, int(round(0.005 * sr)))
    env = np.convolve(a, np.ones(win) / win, mode="same")
    thr = max(500.0, 0.10 * float(env.max()))
    active = env > thr
    segs = []
    i, n = 0, len(active)
    while i < n:
        if active[i]:
            j = i
            while j < n and active[j]:
                j += 1
            segs.append((i, j))
            i = j
        else:
            i += 1
    return segs


def decode_digit(seg, sr):
    """Identify a single DTMF tone by its low/high frequency pair."""
    x = seg.astype(np.float64)
    x = x - x.mean()
    w = np.hanning(len(x))
    spec = np.abs(np.fft.rfft(x * w))
    freqs = np.fft.rfftfreq(len(x), 1.0 / sr)

    def peak(lo, hi):
        m = (freqs >= lo) & (freqs <= hi)
        return float(freqs[m][int(np.argmax(spec[m]))])

    f_lo = peak(600, 1000)
    f_hi = peak(1150, 1700)
    lo = min(LOW, key=lambda f: abs(f - f_lo))
    hi = min(HIGH, key=lambda f: abs(f - f_hi))
    return DTMF_MAP[(lo, hi)]


def decode_blocks(samples, sr):
    """Decode the DTMF, returning one digit string per silence-separated block."""
    segs = digit_segments(samples, sr)
    assert segs, "no DTMF tones detected"
    merge = int(round(MERGE_GAP * sr))
    blocks = []
    cur = [segs[0]]
    for s in segs[1:]:
        if s[0] - cur[-1][1] < merge:
            cur.append(s)
        else:
            blocks.append(cur)
            cur = [s]
    blocks.append(cur)
    return ["".join(decode_digit(samples[a:b], sr) for a, b in blk) for blk in blocks]


def load_keypad(text):
    """Parse the 10-key / 3-column table out of the courier debrief."""
    rows = {}
    for m in re.finditer(r"^\s*key\s*(\d)\s*:\s*(\S)\s+(\S)\s+(\S)\s*$", text, re.M):
        rows[int(m.group(1))] = m.group(2) + m.group(3) + m.group(4)
    assert len(rows) == 10, "could not parse the 10-key keypad table"
    return "".join(rows[k] for k in range(10))


def keypad_decode(digits, keypad):
    out = []
    for i in range(0, len(digits), 2):
        out.append(keypad[int(digits[i]) * 3 + int(digits[i + 1])])
    return "".join(out)


def payload_word_to_flag(payload_digits, word):
    """decimal payload -> bytes -> XOR keystream -> inflate -> flag (or None)."""
    ks = hashlib.sha256(word.encode() + b"payphone").digest()
    n = int(payload_digits)
    raw = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    for pad in range(0, 3):                     # tolerate a lost leading zero byte
        cand = b"\x00" * pad + raw
        x = bytes(c ^ ks[i % 32] for i, c in enumerate(cand))
        try:
            out = zlib.decompress(x)
        except Exception:
            continue
        try:
            txt = out.decode("ascii")
        except Exception:
            continue
        m = re.search(r"FTA\{[a-z0-9_]+\}", txt)
        if m:
            return m.group(0)
    return None


def solve():
    out = L.out_dir("E06")
    samples, sr = read_pcm(out / "payphone.wav")
    text = (out / "EXCHANGE.txt").read_text(encoding="utf-8")

    blocks = decode_blocks(samples, sr)
    assert len(blocks) == 3, ("expected 3 DTMF blocks (handshake/code/payload)", blocks)

    # TRAP #2: the leading handshake block is filler - it must be discarded.
    code_digits = blocks[1]
    payload_digits = blocks[2]
    assert len(code_digits) == 6, code_digits

    keypad = load_keypad(text)
    word = keypad_decode(code_digits, keypad)
    assert len(word) == 3, word

    flag = payload_word_to_flag(payload_digits, word)
    assert flag == L.FLAGS["E06"], ("recovered", flag)
    print("[E06] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
