#!/usr/bin/env python3
"""Solution script for E01 | Lester's Pager Panic
1. Filter dispatch.csv where (col_A * col_B) % col_C == 7
2. Sort rows: primary = col_D % 2 (parity), secondary = col_E descending
3. Decode each payload using the base-41 alphabet recovered from binary
"""
import csv
from pathlib import Path

ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyz_!@#$"
BASE = 41

def decode_b41(s: str) -> bytes:
    val = 0
    for ch in s:
        val = val * BASE + ALPHABET.index(ch)
    return val.to_bytes((val.bit_length() + 7) // 8, 'big')

def solve():
    csv_path = Path("D:/ctf/FLAG_THEFT_AUTO_FINAL/challenges_rebuilt/EASY/E01/dispatch.csv")
    valid_rows = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            a = int(row['col_A'])
            b = int(row['col_B'])
            c = int(row['col_C'])
            if (a * b) % c == 7:
                valid_rows.append(row)

    print(f"[*] Found {len(valid_rows)} genuine rows out of 200")
    # Secondary sort: primary = col_D % 2 (parity), secondary = col_E descending
    valid_rows.sort(key=lambda r: (int(r['col_D']) % 2, -int(r['col_E'])))

    flag_parts = [decode_b41(r['payload']).decode() for r in valid_rows]
    flag = ''.join(flag_parts)
    print(f"[+] Recovered flag: {flag}")
    assert flag == "FTA{41_c1ph3r_b4s3_cust0m_m0d_p4g3r_l3st3r_2026}"
    print("[+] E01 Solved & Verified!")

if __name__ == '__main__':
    solve()
