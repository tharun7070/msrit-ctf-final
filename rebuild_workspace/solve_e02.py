#!/usr/bin/env python3
"""Solution script for E02 | Vinewood Shift Change
1. Find row where SHA1(timestamp) ends with 'a3'
2. Frequency analysis on frequency_sample.bin reveals Affine parameters a=7, b=11
3. Decrypt ciphertext: p = pow(a, -1, 26) * (c - b) % 26
"""
import hashlib
from pathlib import Path

A = 7
B = 11
A_INV = pow(A, -1, 26) # 15

def affine_decrypt(text: str, a_inv: int, b: int) -> str:
    res = []
    for ch in text:
        if 'a' <= ch <= 'z':
            c = ord(ch) - ord('a')
            p = (a_inv * (c - b)) % 26
            res.append(chr(ord('a') + p))
        elif 'A' <= ch <= 'Z':
            c = ord(ch) - ord('A')
            p = (a_inv * (c - b)) % 26
            res.append(chr(ord('A') + p))
        else:
            res.append(ch)
    return ''.join(res)

def solve():
    ledger_path = Path("D:/ctf/FLAG_THEFT_AUTO_FINAL/challenges_rebuilt/EASY/E02/taxi_ledger.txt")
    target_row = None
    for line in ledger_path.read_text(encoding='utf-8').splitlines():
        if not line.strip(): continue
        parts = [p.strip() for p in line.split('|')]
        ts = parts[0]
        if hashlib.sha1(ts.encode()).hexdigest().endswith('a3'):
            target_row = parts
            break

    assert target_row is not None, "Target row not found!"
    ciphertext = target_row[4]
    flag = affine_decrypt(ciphertext, A_INV, B)
    print(f"[+] Found target row timestamp: {target_row[0]}")
    print(f"[+] Decrypted flag: {flag}")
    assert flag == "FTA{4ff1n3_v1n3w00d_sh1ft_c0nv0y_99}"
    print("[+] E02 Solved & Verified!")

if __name__ == '__main__':
    solve()
