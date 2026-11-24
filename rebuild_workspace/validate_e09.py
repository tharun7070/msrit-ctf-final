#!/usr/bin/env python3
"""E09 - Chop Shop Terminal. Validator (private).

  1. Runs solve_e09.py as a fresh subprocess; asserts it prints PASS + the
     canonical flag and exits 0.
  2. NEGATIVE tests:
       a. the dead-branch decoy flag and the printed-comment decoy are both
          FTA{...} strings but NOT the canonical flag;
       b. the real flag never appears verbatim in any artifact;
       c. a WRONG key (seed ^ 1) does not recover the canonical flag;
       d. a WRONG candidate re-encrypts to a different TARGET (checker rejects).
"""
import base64
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
import solve_e09 as S


def main():
    here = Path(__file__).resolve().parent
    out = L.out_dir("E09")
    flag = L.FLAGS["E09"]

    # 1. run the solver as a fresh process
    r = subprocess.run([sys.executable, str(here / "solve_e09.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, "solver exited %d\n%s" % (r.returncode, r.stderr)
    expected = "[E09] PASS -> " + flag
    assert expected in r.stdout, "solver stdout: %r" % r.stdout
    print(r.stdout.strip())

    js = (out / "chopshop.js").read_text(encoding="utf-8")
    html = (out / "terminal.html").read_text(encoding="utf-8")

    # 2a. traps are FTA{...} strings but not the flag
    dead = "FTA{sh0p_b41t_d34d_c0d3}"
    comment = "FTA{c0mm3nt_s4ys_th15}"
    assert dead in js and comment in js, "traps missing"
    assert re.fullmatch(r"FTA\{[a-z0-9_]+\}", dead)
    assert re.fullmatch(r"FTA\{[a-z0-9_]+\}", comment)
    assert dead != flag and comment != flag, "trap equals the flag!"

    # 2b. no verbatim flag in either participant artifact
    assert flag not in js and flag not in html, "flag leaked verbatim!"

    # 2c. wrong key does not recover the flag
    rotated, _ = S.parse_chopshop(js)
    target_hex = rotated[S.IDX_TARGET]
    stored = int(rotated[S.IDX_SEED], 16)
    good_seed = (stored ^ S.SEED_XOR) & 0xFFFFFFFF
    t = bytes.fromhex(target_hex)

    good = bytes(x ^ y for x, y in
                 zip(t, S.xorshift32_keystream(good_seed, len(t))))
    assert base64.b64decode(good).decode() == flag

    bad_seed = good_seed ^ 1
    wrong = bytes(x ^ y for x, y in
                  zip(t, S.xorshift32_keystream(bad_seed, len(t))))
    assert wrong != good, "wrong key produced identical ciphertext!"
    try:
        decoded_wrong = base64.b64decode(wrong).decode("latin-1")
    except Exception:
        decoded_wrong = None
    assert decoded_wrong != flag, "wrong key accepted!"

    # 2d. a wrong candidate yields a different TARGET (checker would DENY)
    from gen_e09 import encrypt
    cand = flag[:-2] + "X}"           # mutate inside the flag body
    assert cand != flag
    assert encrypt(cand.encode()) != target_hex, "wrong candidate accepted!"

    print("[E09] VALIDATE OK (decoys=%r,%r | wrong-key rejected | "
          "wrong-candidate rejected)" % (dead, comment))


if __name__ == "__main__":
    main()
