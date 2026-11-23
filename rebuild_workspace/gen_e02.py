#!/usr/bin/env python3
"""E02: Vinewood Shift Change generator
- taxi_ledger.txt (80 rows)
- frequency_sample.bin (400 chars of English text encrypted with a=7, b=11)
- Timestamp SHA1 ending in 'a3' identifies the genuine row
- Decoy row decrypts with Caesar shift-5 to FTA{wrong_route}
- Genuine row encrypted with Affine c = (7*p + 11) mod 26
"""
import hashlib
import random
from pathlib import Path

OUT_DIR = Path("D:/ctf/FLAG_THEFT_AUTO_FINAL/challenges_rebuilt/EASY/E02")
OUT_DIR.mkdir(parents=True, exist_ok=True)

TRUE_FLAG = "FTA{4ff1n3_v1n3w00d_sh1ft_c0nv0y_99}"
DECOY_FLAG = "FTA{wrong_route}"

A = 7
B = 11

def affine_encrypt(text: str, a: int, b: int) -> str:
    res = []
    for ch in text:
        if 'a' <= ch <= 'z':
            p = ord(ch) - ord('a')
            c = (a * p + b) % 26
            res.append(chr(ord('a') + c))
        elif 'A' <= ch <= 'Z':
            p = ord(ch) - ord('A')
            c = (a * p + b) % 26
            res.append(chr(ord('A') + c))
        else:
            res.append(ch)
    return ''.join(res)

def caesar_encrypt(text: str, shift: int) -> str:
    res = []
    for ch in text:
        if 'a' <= ch <= 'z':
            res.append(chr(ord('a') + (ord(ch) - ord('a') + shift) % 26))
        elif 'A' <= ch <= 'Z':
            res.append(chr(ord('A') + (ord(ch) - ord('A') + shift) % 26))
        else:
            res.append(ch)
    return ''.join(res)

# 1. Generate 400-character sample text for frequency analysis
sample_text = (
    "The midnight fleet leaves Vinewood station every twenty minutes with cash from the casino vault. "
    "Drivers are instructed to maintain radio silence through the hills and verify all drop coordinates. "
    "Lester warned that private security patrols have increased along the freeway interchanges. "
    "Keep all telemetry packets recorded in the dispatch log for end of shift audit and asset reconciliation at dawn."
)
assert len(sample_text) >= 400, f"Sample text too short: {len(sample_text)}"
sample_text = sample_text[:400]
encrypted_sample = affine_encrypt(sample_text, A, B)
(OUT_DIR / "frequency_sample.bin").write_bytes(encrypted_sample.encode('utf-8'))

# 2. Generate 80 taxi ledger rows
random.seed(0x1337_E02)

# Generate timestamps
target_timestamp = None
while True:
    ts = f"2026-11-20T{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}.{random.randint(100,999)}Z"
    h = hashlib.sha1(ts.encode()).hexdigest()
    if h.endswith('a3'):
        target_timestamp = ts
        break

decoy_timestamp = None
while True:
    ts = f"2026-11-20T{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}.{random.randint(100,999)}Z"
    h = hashlib.sha1(ts.encode()).hexdigest()
    if not h.endswith('a3') and ts != target_timestamp:
        decoy_timestamp = ts
        break

other_timestamps = []
while len(other_timestamps) < 78:
    ts = f"2026-11-20T{random.randint(0,23):02d}:{random.randint(0,59):02d}:{random.randint(0,59):02d}.{random.randint(100,999)}Z"
    h = hashlib.sha1(ts.encode()).hexdigest()
    if not h.endswith('a3') and ts not in other_timestamps and ts != decoy_timestamp:
        other_timestamps.append(ts)

rows = []
# Genuine row
rows.append(f"{target_timestamp} | ROUTE-99-ALPHA | CAB-104 | DISPATCHED | {affine_encrypt(TRUE_FLAG, A, B)}")
# Decoy row (decrypts with shift-5)
rows.append(f"{decoy_timestamp} | ROUTE-05-BRAVO | CAB-077 | TERMINATED | {caesar_encrypt(DECOY_FLAG, 5)}")

# Fill remaining 78 rows
for i, ts in enumerate(other_timestamps):
    cab_id = f"CAB-{random.randint(101, 899)}"
    route = f"ROUTE-{random.randint(10, 89)}"
    status = random.choice(["EN_ROUTE", "IDLE", "STANDBY", "PAUSED", "OFFLINE"])
    noise_msg = f"TRANSIT_NOTE_{random.randint(1000, 9999)}_SIGNAL_LOSS_{random.randint(100, 999)}"
    enc_noise = affine_encrypt(noise_msg, random.choice([3, 5, 9]), random.randint(1, 25))
    rows.append(f"{ts} | {route} | {cab_id} | {status} | {enc_noise}")

random.shuffle(rows)
ledger_path = OUT_DIR / "taxi_ledger.txt"
ledger_path.write_text('\n'.join(rows) + '\n', encoding='utf-8')

print(f"[+] Wrote 80 rows to {ledger_path}")
print(f"[+] Target timestamp SHA-1: {hashlib.sha1(target_timestamp.encode()).hexdigest()}")
print(f"[+] True flag: {TRUE_FLAG}")
