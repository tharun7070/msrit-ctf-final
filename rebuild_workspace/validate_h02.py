#!/usr/bin/env python3
"""H02 validation harness.

Runs the reference solver, checks the returned flag equals L.FLAGS["H02"],
checks that a wrong flag is rejected, and asserts the literal flag/body never
appears in any participant-facing file under out_dir("H02").
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
import solve_h02


def accepted(candidate: str) -> bool:
    """The CTFd-style acceptance test (exact match against the canonical flag)."""
    return candidate == L.FLAGS["H02"]


def main():
    out = L.out_dir("H02")
    good = solve_h02.solve()                       # full solve path
    assert accepted(good), good

    # a plausible but wrong assembly: fragments read in reverse template order
    body = good[4:-1]
    wrong = "FTA{" + body[::-1] + "}"
    assert wrong != good
    assert not accepted(wrong), "wrong flag was accepted!"
    # another wrong variant: shuffle the first two fragments' positions
    assert not accepted("FTA{" + body[2:] + body[:2] + "}")

    # the flag body must not be greppable in any participant-facing file
    flag, lit_body = L.FLAGS["H02"], L.FLAGS["H02"][4:-1]
    checked = 0
    for p in sorted(out.rglob("*")):
        if not p.is_file():
            continue
        txt = p.read_text(encoding="utf-8", errors="ignore")
        assert flag not in txt, f"literal flag leaked into {p.name}"
        assert lit_body not in txt, f"literal body leaked into {p.name}"
        checked += 1

    print(f"[H02] validated: solver PASS, wrong flag rejected, "
          f"{checked} participant files clean of the flag body")
    print("[H02] VALIDATION OK")


if __name__ == "__main__":
    main()
