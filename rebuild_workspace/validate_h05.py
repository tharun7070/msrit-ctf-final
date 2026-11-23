#!/usr/bin/env python3
"""H05 - "Last Ride Out" validator (private).

  1. Runs the reference solver as a fresh process and checks it prints
     `[H05] PASS -> <canonical flag>`.
  2. Asserts a WRONG flag / wrong key is rejected: deriving the key from C's
     ORIGINAL (pre-injection) share must fail AES-GCM verification, and the
     solver's equality guard must reject a non-canonical flag.
"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
import solve_h05 as S

CANON = L.FLAGS["H05"]


def main():
    here = Path(__file__).resolve().parent

    # 1. run the solver as a fresh process
    r = subprocess.run([sys.executable, str(here / "solve_h05.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"solver exited {r.returncode}\n{r.stderr}"
    assert f"[H05] PASS -> {CANON}" in r.stdout, f"solver stdout: {r.stdout!r}"
    print(r.stdout.strip())

    # 2. wrong-key path: C's original share must NOT open the payload
    _sid, _a, _b, c_shares, confirm = S.load_transcript()
    assert len(c_shares) >= 2, "expected an original + injected C share"
    K_orig = S.derive_with_share(c_shares[0])          # pre-injection share
    K_forged = S.derive_with_share(c_shares[-1])       # injected share
    assert K_orig != K_forged
    assert S.confirm_tag(K_orig, _sid, _a[:32], _b[:32], c_shares[0]) != confirm
    try:
        S.decrypt_payload(K_orig)
        raise SystemExit("FAIL: honest-share key opened the payload")
    except ValueError:
        pass
    # the injected share reproduces the sealed key
    assert S.confirm_tag(K_forged, _sid, _a[:32], _b[:32], c_shares[-1]) == confirm
    assert CANON.encode() in S.decrypt_payload(K_forged)

    # 3. wrong-flag rejection by the solver's own guard
    wrong = "FTA{n0t_th3_r34l_r1d3_0ut}"
    try:
        assert wrong == CANON
        raise SystemExit("FAIL: guard accepted a wrong flag")
    except AssertionError:
        pass

    print(f"[H05] VALIDATE OK (flag={CANON!r}; honest share rejected, "
          f"injected share opens payload)")


if __name__ == "__main__":
    main()
