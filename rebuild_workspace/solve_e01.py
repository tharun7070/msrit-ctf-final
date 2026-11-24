#!/usr/bin/env python3
"""E01 reference solver (participant-reproducible).

Faithful inverse of gen_e01.py:
  * genuine rows satisfy BOTH congruences:
        (col_A*col_B)%col_C == 7   AND   (col_A+col_B)%col_C == (col_D%col_C);
  * genuine rows are ordered by (col_C%5 asc, col_D%2 asc, -col_E desc, packet_id asc);
  * each payload is un-permuted with the inverse affine map over the 41-symbol
    alphabet (idx = k^-1 * (y - m) mod 41, k = 1+col_A%40, m = col_D%41) and then
    base-41 decoded;
  * the concatenated plaintext carries a fixed 2-byte marker that is stripped.
"""
import csv, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

CHUNK = 7
MARKER = b"\x1b\x13"


def _unpermute(text, k, m):
    a = L.BASE41_ALPHABET
    ki = pow(k, -1, L.BASE41)
    return "".join(a[(ki * (a.index(ch) - m)) % L.BASE41] for ch in text)


def solve():
    flag = L.FLAGS["E01"]
    n_chunks = (len(MARKER) + len(flag.encode()) + CHUNK - 1) // CHUNK

    p = L.out_dir("E01") / "dispatch.csv"
    rows = list(csv.DictReader(p.open(newline="")))

    # Layer 1: keep only rows that satisfy BOTH congruences.
    genuine = [
        r for r in rows
        if (int(r["col_A"]) * int(r["col_B"])) % int(r["col_C"]) == 7
        and (int(r["col_A"]) + int(r["col_B"])) % int(r["col_C"]) == int(r["col_D"]) % int(r["col_C"])
    ]
    assert len(genuine) == n_chunks, len(genuine)

    # Layer 3: triple-key ordering with a deterministic packet_id tie-break.
    genuine.sort(key=lambda r: (int(r["col_C"]) % 5, int(r["col_D"]) % 2,
                                -int(r["col_E"]), r["packet_id"]))

    # Layer 2: invert the per-row affine permutation, then base-41 decode.
    plain = bytearray()
    for r in genuine:
        k = 1 + (int(r["col_A"]) % 40)
        m = int(r["col_D"]) % 41
        plain += L.base41_decode(_unpermute(r["payload"], k, m))

    # Layer 3 (cont.): strip the fixed marker pad.
    assert bytes(plain[:len(MARKER)]) == MARKER, bytes(plain[:len(MARKER)])
    recovered = bytes(plain[len(MARKER):]).decode()
    assert recovered == flag, recovered
    print("[E01] PASS ->", recovered)
    return recovered


if __name__ == "__main__":
    solve()
