#!/usr/bin/env python3
"""M03 - LSPD Midnight Audit. Validator (private).

  1. Runs the reference solver end to end and checks it prints PASS + the
     canonical flag.
  2. Independently recovers the salt, verifies the keyed chain and every block
     root, confirms the forgeries span more than one checkpoint block, repairs
     them via the nested delta and re-derives the flag.
  3. Asserts a WRONG flag is rejected (a mis-repaired log decodes to something
     else and the solver's equality guard would fire).
  4. Asserts the decoy path (naive substring 'endswith ACCEPT' + adjacent XOR)
     collapses to a fake FTA{...}, never the canonical flag.
"""
import string
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
import solve_m03 as S


def naive_flag(lines) -> str:
    """The trap: substring match on 'ACCEPT' catches the _REACCEPT decoys."""
    chars = [ln.split("|")[2][0] for ln in lines
             if ln.split("|")[2].endswith("ACCEPT")]
    return "".join(chr(ord(chars[i]) ^ ord(chars[i + 1]))
                   for i in range(0, len(chars) - 1, 2))


def flip_same_class(line: str) -> str:
    """Rewrite an ACCEPT code's first char, keeping its hash class, so the
    columns stay even but the decoded byte changes."""
    f = line.split("|")
    oc = f[2]
    cls = S.code_class(oc)
    for cand in string.ascii_letters + string.digits:
        if cand != oc[0] and S.code_class(f"{cand}_ACCEPT") == cls:
            f[2] = f"{cand}_ACCEPT"
            return "|".join(f)
    raise AssertionError("no same-class alternate found")


def main():
    here = Path(__file__).resolve().parent

    # 1. run the solver as a fresh process
    r = subprocess.run([sys.executable, str(here / "solve_m03.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"solver exited {r.returncode}\n{r.stderr}"
    expected = f"[M03] PASS -> {L.FLAGS['M03']}"
    assert expected in r.stdout, f"solver stdout: {r.stdout!r}"
    print(r.stdout.strip())

    # 2. independent recomputation
    lines = S.read_log()
    roots = S.read_roots()
    key = S.recover_salt(lines, roots[0])
    delta = S.parse_delta((L.out_dir("M03") / "audit_delta.bin").read_bytes())

    breaks = S.find_breaks(lines, key)
    assert len(breaks) == 3, breaks
    blocks = {(i // S.BLOCK) + 1 for i in breaks}
    assert len(blocks) >= 2, f"forgeries confined to one block: {blocks}"
    assert not S.verify_roots(lines, key, roots), "roots were not broken"

    repaired = S.repair(lines, delta, key)
    assert S.find_breaks(repaired, key) == [], "chain still broken after repair"
    assert S.verify_roots(repaired, key, roots), "block roots still broken"

    good = S.decode_flag(repaired)
    assert good == L.FLAGS["M03"], good

    # 3. wrong-flag rejection (same hash class -> columns stay even)
    bad_lines = list(repaired)
    for i, ln in enumerate(bad_lines):
        if ln.split("|")[2].endswith("_ACCEPT"):
            bad_lines[i] = flip_same_class(ln)
            break
    wrong = S.decode_flag(bad_lines)
    assert wrong != L.FLAGS["M03"], "wrong flag was NOT rejected"

    try:
        assert wrong == L.FLAGS["M03"]
        raise SystemExit("FAIL: guard accepted a wrong flag")
    except AssertionError:
        pass

    # 4. decoy trap must not collapse onto the canonical flag
    decoy = naive_flag(repaired)
    assert decoy.startswith("FTA{"), decoy
    assert decoy != L.FLAGS["M03"], "decoy collapsed onto the real flag"
    print(f"[M03] decoy path -> {decoy!r} (rejected)")

    print(f"[M03] VALIDATE OK (good={good!r}, wrong rejected={wrong!r})")


if __name__ == "__main__":
    main()
