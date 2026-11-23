#!/usr/bin/env python3
"""M02 — Airport Ghost Flight. Validator (private).

1. Runs `gen_m02.py` is assumed already executed (or the pcap exists).
2. Runs `solve_m02.py` as a subprocess and asserts a clean exit + exact output.
3. Imports the solver and asserts the decoded value equals L.FLAGS["M02"].
4. Asserts the grading check rejects a wrong/mutated flag (and rejects the
   decoy material that a naive solver might return).
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lib_fta as L
from solve_m02 import solve, extract_fragments


def accepts(candidate: str) -> bool:
    """Mimics the CTFd exact-match check for M02."""
    return candidate == L.FLAGS["M02"]


def main():
    pcap = L.out_dir("M02") / "airport_traffic.pcap"
    assert pcap.exists(), f"missing {pcap}; run gen_m02.py first"

    # --- run the reference solver as a real process -------------------------
    proc = subprocess.run(
        [sys.executable, str(HERE / "solve_m02.py")],
        capture_output=True, text=True,
    )
    print(proc.stdout.strip())
    assert proc.returncode == 0, f"solver exit {proc.returncode}\n{proc.stderr}"
    expected_line = f"[M02] PASS -> {L.FLAGS['M02']}"
    assert expected_line in proc.stdout, f"missing PASS line: {proc.stdout!r}"

    # --- in-process solve ----------------------------------------------------
    flag = solve()
    assert flag == L.FLAGS["M02"], flag

    # --- the gate must accept the real flag and reject anything else ---------
    assert accepts(flag), "gate rejected the genuine flag"

    wrong_flags = [
        flag[:-1] + ("x" if flag[-1] != "x" else "y"),  # last char mutated
        flag.replace("gh0st", "gh0ost"),                # insertion
        "",                                             # empty
        flag.upper(),                                   # case tweak
        "FTA{wrong_flag}",                              # arbitrary
    ]
    for w in wrong_flags:
        assert w != flag, "mutated flag collided"
        assert not accepts(w), f"gate wrongly accepted {w!r}"
    print(f"[M02] rejected {len(wrong_flags)} wrong answers")

    # --- sanity: decoys are present and are correctly ignored ---------------
    frags, stats = extract_fragments(pcap)
    assert stats["frames"] > len(frags), (
        "expected decoy frames to be parsed but not accepted: "
        f"{stats}"
    )
    assert len(frags) > 1 and stats["payloads"] >= len(frags), stats
    print(f"[M02] {stats} accepted_fragments={len(frags)}")

    print("[M02] VALIDATION OK")


if __name__ == "__main__":
    main()
