#!/usr/bin/env python3
"""E10 "Towing Yard Ignition" -- validator (private organizer tooling).

  1. Runs the reference solver (`solve_e10.py`) as a FRESH subprocess and
     asserts it prints exactly "[E10] PASS -> <canonical flag>".
  2. NEGATIVE tests (>= 2):
       a) the naive VM prescribed by the (trap) workspace note -- wrong opcode
          table + verbatim operands/header -- yields the DECOY phrase and
          FAILS the embedded FNV-1a-32 checksum gate;
       b) the corrected VM run against a single tampered header byte also
          FAILS the gate and yields the DECOY (proves the gate is live);
       c) the PROVIDED `disassemble.py` (wrong table) reports GATE FAILED and
          emits the DECOY phrase to stdout.
  3. Asserts the REAL flag never appears verbatim in any shipped artifact.
"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
import solve_e10 as S

FLAG = L.FLAGS["E10"]


def main():
    here = Path(__file__).resolve().parent
    out = L.out_dir("E10")

    # -- 1. reference solver, fresh process ---------------------------------
    r = subprocess.run([sys.executable, str(here / "solve_e10.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, "solver exited %d\n%s" % (r.returncode, r.stderr)
    expected = "[E10] PASS -> %s" % FLAG
    assert expected in r.stdout, "solver stdout: %r" % r.stdout
    print(r.stdout.strip())

    vmb = (out / "ignition.vmb").read_bytes()

    # -- 2a. naive VM (trap note): wrong table + verbatim operands/header ---
    decoy, ok = S.vm_run(vmb, S.WRONG_TABLE, S.NAIVE_ENC)
    assert ok is False, "naive VM unexpectedly passed the integrity gate"
    assert decoy == S.DECOY, "naive VM did not emit the decoy: %r" % decoy
    assert decoy != FLAG, "decoy equals the real flag"
    print("  [neg-1] naive VM (note table/encoding) -> decoy, gate FAILED")

    # -- 2b. correct VM, one tampered header byte (CONST) -------------------
    bad = bytearray(vmb)
    bad[5] ^= 0xFF                                # flip a CONST byte
    decoy2, ok2 = S.vm_run(bytes(bad), S.TRUE_TABLE, S.CORRECT_ENC)
    assert ok2 is False, "tampered header unexpectedly passed the gate"
    assert decoy2 == S.DECOY, "tampered header did not emit the decoy: %r" % decoy2
    print("  [neg-2] tampered CONST byte -> decoy, gate FAILED")

    # -- 2c. provided disassembler (wrong table) ----------------------------
    r2 = subprocess.run([sys.executable, str(out / "disassemble.py")],
                        capture_output=True, text=True)
    assert r2.returncode == 0, "disassemble.py exited %d\n%s" % (r2.returncode, r2.stderr)
    assert S.DECOY in r2.stdout, "disassemble.py did not surface the decoy"
    assert "GATE FAILED" in r2.stdout, "disassemble.py did not report gate failure"
    assert FLAG not in r2.stdout, "disassemble.py leaked the real flag"
    print("  [neg-3] provided disassemble.py -> GATE FAILED + decoy")

    # -- 3. anti-leak: real flag must not appear verbatim in any artifact ---
    for name in ("ignition.vmb", "YARD_NOTES.txt", "disassemble.py"):
        blob = (out / name).read_bytes()
        assert FLAG.encode() not in blob, "flag leaked verbatim into %s" % name

    print("[E10] VALIDATE OK")


if __name__ == "__main__":
    main()
