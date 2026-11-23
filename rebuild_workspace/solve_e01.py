#!/usr/bin/env python3
"""E01 reference solver (participant-reproducible)."""
import csv, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

def solve():
    p = L.out_dir("E01") / "dispatch.csv"
    rows = list(csv.DictReader(p.open(newline="")))
    genuine = [r for r in rows if (int(r["col_A"]) * int(r["col_B"])) % int(r["col_C"]) == 7]
    assert len(genuine) == (len(L.FLAGS["E01"]) + 6) // 7, len(genuine)
    genuine.sort(key=lambda r: (int(r["col_D"]) % 2, -int(r["col_E"])))
    flag = "".join(L.base41_decode(r["payload"]).decode() for r in genuine)
    assert flag == L.FLAGS["E01"], flag
    print("[E01] PASS ->", flag)
    return flag

if __name__ == "__main__":
    solve()
