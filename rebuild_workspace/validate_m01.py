#!/usr/bin/env python3
"""M01 validator: runs the reference solver and asserts a wrong flag is rejected."""
import sys
from pathlib import Path

sys.path.insert(0, r"d:\ctf\FLAG_THEFT_AUTO_FINAL\rebuild_workspace")
import lib_fta as L
import solve_m01


def main() -> int:
    flag = solve_m01.solve()
    solve_m01.check(flag)
    assert flag == L.FLAGS["M01"], flag

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
    print(f"[M01] VALIDATE OK (good='{flag}', wrong rejected={rejected})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
