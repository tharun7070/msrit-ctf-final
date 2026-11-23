#!/usr/bin/env python3
"""H03 validator — runs the reference solver and proves a wrong answer is
rejected. Also asserts the flag never leaks into the participant directory."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
from solve_h03 import solve


def submit(candidate: str) -> bool:
    """Simulated CTFd answer check (exact match, case-sensitive)."""
    return candidate == L.FLAGS["H03"]


def main():
    good = solve()
    assert good == L.FLAGS["H03"], good
    assert submit(good) is True

    # wrong answers must be rejected
    wrong = ("X" + good[1:])
    assert wrong != good
    assert submit(wrong) is False
    assert submit(good.lower()) is False
    assert submit(good.rstrip("}")) is False

    # the flag must not appear verbatim in any participant file
    for p in L.out_dir("H03").iterdir():
        if p.is_file():
            assert L.FLAGS["H03"].encode() not in p.read_bytes(), f"leak in {p.name}"

    print(f"[H03] VALIDATE OK (good='{good}', wrong rejected='{wrong}')")


if __name__ == "__main__":
    main()
