#!/usr/bin/env python3
"""M03 - LSPD Midnight Audit. Validator (private).

  1. Runs the reference solver end to end and checks it prints PASS + the
     canonical flag.
  2. Asserts a WRONG flag is rejected: decode a deliberately mis-repaired log
     and confirm it does NOT match the canonical flag (and that the solver's
     equality assertion would fire on it).
"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
import solve_m03 as S


def main():
    here = Path(__file__).resolve().parent

    # 1. run the solver as a fresh process
    r = subprocess.run([sys.executable, str(here / "solve_m03.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"solver exited {r.returncode}\n{r.stderr}"
    expected = f"[M03] PASS -> {L.FLAGS['M03']}"
    assert expected in r.stdout, f"solver stdout: {r.stdout!r}"
    print(r.stdout.strip())

    # 2. wrong-flag rejection
    lines = S.read_log()
    delta = S.parse_delta((L.out_dir("M03") / "audit_delta.bin").read_bytes())
    repaired = S.repair(lines, delta)

    good = S.decode_flag(repaired)
    assert good == L.FLAGS["M03"], good

    # tamper the repaired log: flip the first ACCEPT share -> decode must differ
    bad_lines = list(repaired)
    for i, ln in enumerate(bad_lines):
        f = ln.split("|")
        if f[2].endswith("_ACCEPT"):
            f[2] = "Z_ACCEPT" if f[2][0] != "Z" else "Q_ACCEPT"
            bad_lines[i] = "|".join(f)
            break
    wrong = S.decode_flag(bad_lines)
    assert wrong != L.FLAGS["M03"], "wrong flag was NOT rejected"

    # emulate the solver's guard on a wrong flag
    try:
        assert wrong == L.FLAGS["M03"]
        raise SystemExit("FAIL: guard accepted a wrong flag")
    except AssertionError:
        pass

    print(f"[M03] VALIDATE OK (good={good!r}, wrong rejected={wrong!r})")


if __name__ == "__main__":
    main()
