#!/usr/bin/env python3
"""M05 validation harness.

Checks:
  1. solve_m05.py runs to completion and prints ``[M05] PASS -> <flag>``.
  2. A wrong flag is rejected by the solver's verification.
  3. broken_dispatch.py is *reliably* wrong: run in an isolated temp copy
     several times and confirm it never reproduces the correct out.bin.
"""
import base64
import json
import shutil
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lib_fta as L
import solve_m05

M05_DIR = L.out_dir("M05")
RUNS = 8


def _manifest(blob: bytes) -> dict:
    return json.loads(zlib.decompress(base64.b85decode(blob)))


def main():
    expected = L.FLAGS["M05"]

    # 1. solver runs cleanly
    r = subprocess.run([sys.executable, str(HERE / "solve_m05.py")],
                       cwd=str(HERE), capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "[M05] PASS -> " + expected in r.stdout, r.stdout
    print("[validate] solver OK:", r.stdout.strip())

    # 2. wrong flag rejected
    try:
        solve_m05.verify(expected + "x")
    except AssertionError:
        pass
    else:
        raise SystemExit("[validate] wrong flag was accepted!")
    print("[validate] wrong flag rejected")

    # 3. broken dispatcher is reliably wrong
    correct_blob = solve_m05.build_correct_out_bin()
    correct_src = base64.b64decode(_manifest(correct_blob)["stage2_b64"])
    wrong = 0
    for _ in range(RUNS):
        with tempfile.TemporaryDirectory() as td:
            shutil.copy(M05_DIR / "broken_dispatch.py", td)
            shutil.copy(M05_DIR / "dispatch_packets.json", td)
            rr = subprocess.run([sys.executable, str(Path(td) / "broken_dispatch.py")],
                                cwd=td, capture_output=True, text=True)
            assert rr.returncode == 0, rr.stderr
            blob = (Path(td) / "out.bin").read_bytes()
            man = _manifest(blob)
            src = base64.b64decode(man["stage2_b64"])
            if man["dispatched"] != 1200 or src != correct_src:
                wrong += 1
    assert wrong == RUNS, "race not reliably visible: %d/%d" % (wrong, RUNS)
    print("[validate] broken_dispatch wrong in %d/%d runs" % (wrong, RUNS))

    print("[validate] M05 VALIDATE OK (flag=%s)" % expected)


if __name__ == "__main__":
    main()
