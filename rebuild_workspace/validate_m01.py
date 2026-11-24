#!/usr/bin/env python3
"""M01 validator: runs the reference solver, asserts the negative paths stay
dead, and that a wrong flag is rejected."""
import re
import sys
from pathlib import Path

sys.path.insert(0, r"d:\ctf\FLAG_THEFT_AUTO_FINAL\rebuild_workspace")
import lib_fta as L
import solve_m01

FTA_RE = re.compile(r"FTA\{[a-z0-9_]+\}")


def main() -> int:
    flag = solve_m01.solve()
    solve_m01.check(flag)
    assert flag == L.FLAGS["M01"], flag

    # Negative case 1: the raw payload (not composed through the write-side
    # transform) must NOT reach the real ledger's veiled row.
    naive_out = solve_m01.naive_attempt()
    assert L.FLAGS["M01"] not in naive_out, "naive payload reached the real ledger"

    # Negative case 2: the decoy `escrow` ledger must serve only decoy data
    # (and trip the canary), never the real flag.
    canary_out = solve_m01.canary_attempt()
    assert L.FLAGS["M01"] not in canary_out, "canary/decoy ledger leaked the real flag"
    assert solve_m01.SRC.joinpath("fleeca_kiosk.py").exists()
    assert "escrow" in canary_out.lower(), "decoy escrow path was not exercised"

    wrong = [
        flag[:-1] + "X",
        flag.replace("fl33c4", "fl33ca"),
        "FTA{" + flag[4:-1][::-1] + "}",
        "",
    ]
    rejected = 0
    for w in wrong:
        try:
            solve_m01.check(w)
        except AssertionError:
            rejected += 1
    assert rejected == len(wrong), "a wrong flag was accepted"
    print(
        f"[M01] VALIDATE OK (good='{flag}', wrong rejected={rejected}, "
        f"naive dead, canary dead)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
