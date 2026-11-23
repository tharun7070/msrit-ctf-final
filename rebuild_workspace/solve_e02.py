#!/usr/bin/env python3
"""E02 reference solver: checksum-filtered row + affine inverse."""
import hashlib, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

def solve():
    p = L.out_dir("E02") / "taxi_ledger.txt"
    target = None
    for line in p.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        tstamp, _, _, _, payload = [x.strip() for x in line.split("|")]
        if hashlib.sha1(tstamp.encode()).hexdigest().endswith("a3"):
            target = (tstamp, payload)
            break
    assert target, "no checksum-matching row"
    flag = L.affine_dec(target[1], 7, 11)
    assert flag == L.FLAGS["E02"], flag
    print("[E02] PASS ->", flag)
    return flag

if __name__ == "__main__":
    solve()
