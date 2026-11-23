#!/usr/bin/env python3
"""E01: Lester's Pager Panic generator
Rebuilt to Hard/Extreme difficulty:
- 200 row CSV dispatch.csv
- Genuine courier rows satisfy (col_A * col_B) % col_C == 7
- Decoded using custom Base-41 alphabet
- Order determined by: primary = parity of col_D (0 then 1), secondary = col_E descending
- Linux ELF binary 'decoder' compiled and stripped
"""
import csv
import random
from pathlib import Path

ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz_!@#$"
BASE = 41
FLAG = "FTA{41_c1ph3r_b4s3_m0d_p4g3r_2026}"

OUT_DIR = Path("D:/ctf/FLAG_THEFT_AUTO_FINAL/challenges_rebuilt/EASY/E01")
OUT_DIR.mkdir(parents=True, exist_ok=True)

def encode_b41(b: bytes) -> str:
    val = int.from_bytes(b, 'big')
    if val == 0:
        return ALPHABET[0]
    digits = []
    while val > 0:
        digits.append(ALPHABET[val % BASE])
        val //= BASE
    return ''.join(reversed(digits))

# Split flag into 8 clean chunks
chunks = [
    b'FTA{41_',
    b'c1ph3r_',
    b'b4s3_',
    b'cust0m_',
    b'm0d_',
    b'p4g3r_',
    b'l3st3r_',
    b'2026}'
]
full_flag = b''.join(chunks).decode()

# We need 8 genuine rows ordered by: parity of col_D (0 then 1), secondary col_E descending
# Let's assign:
# First 4 chunks: col_D is even (parity 0), col_E decreasing: 950, 820, 710, 600
# Next 4 chunks: col_D is odd (parity 1), col_E decreasing: 910, 780, 650, 520
genuine_sorting = [
    (100, 950), # parity 0, col_E 950 -> chunk 0
    (102, 820), # parity 0, col_E 820 -> chunk 1
    (104, 710), # parity 0, col_E 710 -> chunk 2
    (106, 600), # parity 0, col_E 600 -> chunk 3
    (101, 910), # parity 1, col_E 910 -> chunk 4
    (103, 780), # parity 1, col_E 780 -> chunk 5
    (105, 650), # parity 1, col_E 650 -> chunk 6
    (107, 520), # parity 1, col_E 520 -> chunk 7
]

random.seed(0x1337_E01)

rows = []
# Create 8 genuine rows
for i, chunk in enumerate(chunks):
    col_d, col_e = genuine_sorting[i]
    enc_payload = encode_b41(chunk)
    # Find col_A, col_B, col_C such that (col_A * col_B) % col_C == 7
    while True:
        col_c = random.randint(30, 200)
        col_a = random.randint(10, 500)
        col_b = random.randint(10, 500)
        if (col_a * col_b) % col_c == 7:
            break
    rows.append({
        'packet_id': f'PKT-{random.randint(10000, 99999)}',
        'col_A': col_a,
        'col_B': col_b,
        'col_C': col_c,
        'col_D': col_d,
        'col_E': col_e,
        'payload': enc_payload,
        'is_genuine': True,
        'chunk_idx': i
    })

# Now generate 192 decoy rows where (col_A * col_B) % col_C != 7
for _ in range(192):
    while True:
        col_c = random.randint(30, 200)
        col_a = random.randint(10, 500)
        col_b = random.randint(10, 500)
        if (col_a * col_b) % col_c != 7:
            break
    col_d = random.randint(10, 999)
    col_e = random.randint(100, 999)
    # Decoy payload: random base-41 characters
    decoy_len = random.randint(5, 9)
    decoy_payload = ''.join(random.choice(ALPHABET) for _ in range(decoy_len))
    rows.append({
        'packet_id': f'PKT-{random.randint(10000, 99999)}',
        'col_A': col_a,
        'col_B': col_b,
        'col_C': col_c,
        'col_D': col_d,
        'col_E': col_e,
        'payload': decoy_payload,
        'is_genuine': False,
        'chunk_idx': -1
    })

# Shuffle all 200 rows
random.shuffle(rows)

# Write dispatch.csv
csv_path = OUT_DIR / "dispatch.csv"
with open(csv_path, 'w', newline='', encoding='utf-8') as f:
    writer = csv.writer(f)
    writer.writerow(['packet_id', 'col_A', 'col_B', 'col_C', 'col_D', 'col_E', 'payload'])
    for r in rows:
        writer.writerow([r['packet_id'], r['col_A'], r['col_B'], r['col_C'], r['col_D'], r['col_E'], r['payload']])

print(f"[+] Wrote 200 rows to {csv_path}")
print(f"[+] Actual target flag: {full_flag}")
