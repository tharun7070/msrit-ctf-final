#!/usr/bin/env python3
"""H02 validation harness.

Checks the hardened challenge end-to-end:

  * the reference solver reconstructs the canonical flag;
  * every planted decoy is REJECTED - the naive ascending-junction-id reading
    (TRAP 1), the scaled dead-end district read in its own correct order
    (TRAP 2), plus reversed / rotated re-assemblies of the true body;
  * no participant-facing file under out_dir("H02") contains the literal flag,
    its body, or either assembled decoy token (anti-leak).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
import solve_h02
import gen_h02


def accepted(candidate: str) -> bool:
    """The CTFd-style acceptance test (exact match against the canonical flag)."""
    return candidate == L.FLAGS["H02"]


def main():
    out = L.out_dir("H02")
    good = solve_h02.solve()                       # full solve path
    assert accepted(good), good

    body = L.FLAGS["H02"][4:-1]

    # plain wrong re-assemblies of the true body
    assert not accepted("FTA{" + body[::-1] + "}")          # reversed
    assert not accepted("FTA{" + body[2:] + body[:2] + "}")  # rotated

    # TRAP 1: naive ascending-junction-id reading (exactly what the bait
    # PROTOCOL.md field note tells an automated solver to submit)
    decoy_index = "FTA{" + gen_h02.DECOY_INDEX + "}"
    assert decoy_index != good
    assert not accepted(decoy_index), "naive index-order decoy was accepted!"

    # TRAP 2: the scaled dead-end district, read in its own (correct) order
    decoy_scale = "FTA{" + gen_h02.DECOY_SCALE + "}"
    assert decoy_scale != good and decoy_scale != decoy_index
    assert not accepted(decoy_scale), "scaled dead-end decoy was accepted!"

    # anti-leak: literal flag, body, and both assembled decoy tokens must be
    # absent from every participant-facing artefact
    flag = L.FLAGS["H02"]
    needles = [flag, body, gen_h02.DECOY_INDEX, gen_h02.DECOY_SCALE]
    checked = 0
    for p in sorted(out.rglob("*")):
        if not p.is_file():
            continue
        txt = p.read_text(encoding="utf-8", errors="ignore")
        for needle in needles:
            assert needle not in txt, f"{needle!r} leaked into {p.name}"
        checked += 1

    print(f"[H02] solver PASS; decoys rejected: index(TRAP1), scale(TRAP2), "
          f"reversed, rotated")
    print(f"[H02] {checked} participant files clean of flag body + decoys")
    print("[H02] VALIDATION OK")


if __name__ == "__main__":
    main()
