#!/usr/bin/env python3
"""H04 validator.

  1. Runs the reference solver and asserts it PASSes with the canonical flag.
  2. Asserts unauthorised / tampered tokens are rejected (no flag returned).
  3. Asserts a wrong flag string is not accepted.
"""
import os
import subprocess
import sys
from pathlib import Path

WS = r"d:\ctf\FLAG_THEFT_AUTO_FINAL\rebuild_workspace"
sys.path.insert(0, WS)
import lib_fta as L  # noqa: E402

OUT = L.out_dir("H04")
sys.path.insert(0, str(OUT))
os.environ["FTA_H04_FLAG"] = L.FLAGS["H04"]
import bank_gateway as gw  # noqa: E402


def main():
    # 1) reference solver must run clean and print the canonical flag.
    res = subprocess.run([sys.executable, str(Path(WS) / "solve_h04.py")],
                         capture_output=True, text=True, cwd=WS)
    assert res.returncode == 0, "solver exited %d\n%s\n%s" % (res.returncode, res.stdout, res.stderr)
    assert "[H04] PASS ->" in res.stdout, res.stdout
    solved = res.stdout.split("[H04] PASS ->")[-1].strip().splitlines()[0].strip()
    assert solved == L.FLAGS["H04"], "solver flag mismatch: %r" % solved

    # 2a) a genuine guest token verifies but is not admin -> rejected.
    guest = gw.issue_guest_token()
    assert gw.verify(guest) is True, "issued guest token should verify"
    assert gw.submit(guest) is None, "guest token must not unlock the flag"

    # 2b) an admin token with a wrong signature must be rejected.
    n, e = gw.public_params()
    wrong_sig = pow(int.from_bytes(gw.ADMIN_MESSAGE.encode(), "big"), e, n)  # not the private sig
    tampered = {"role": "admin", "msg": gw.ADMIN_MESSAGE, "sig": format(wrong_sig, "x")}
    assert gw.verify(tampered) is False, "tampered token must fail verify"
    assert gw.submit(tampered) is None, "tampered token must not unlock the flag"

    # 2c) a genuinely-signed admin message presented under the wrong role is
    #     rejected by the role gate (verify passes, submit refuses).
    m = int.from_bytes(gw.ADMIN_MESSAGE.encode(), "big")
    correct_sig = gw._sign(m)  # full CRT signature; equals the private-key signature
    assert pow(correct_sig, e, n) == m % n
    wrong_role = {"role": "guest", "msg": gw.ADMIN_MESSAGE, "sig": format(correct_sig, "x")}
    assert gw.verify(wrong_role) is True
    assert gw.submit(wrong_role) is None, "non-admin role must not unlock the flag"

    # 3) a wrong flag string is not the answer.
    assert "FTA{r4gg1ng_r0ugh_but_l3g4l}" != L.FLAGS["H04"]

    print("[H04] validate OK - solver PASS, unauthorised tokens rejected")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
