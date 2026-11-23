#!/usr/bin/env python3
"""H01 "Zancudo Deadbolt" -- validation harness (organizer).

Checks, end to end:
  1. ``gen_h01.py`` builds the stripped ELF (and the participant OPERATIONS.txt).
  2. ``solve_h01.py`` recovers the passphrase and prints PASS.
  3. the live gate accepts the correct passphrase (success banner, exit 0).
  4. the live gate rejects a set of near-miss / wrong passphrases.
  5. the plaintext flag appears in no participant file (raw bytes + ``strings``).
"""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, r"d:\ctf\FLAG_THEFT_AUTO_FINAL\rebuild_workspace")
import lib_fta as L

WS = Path(r"d:\ctf\FLAG_THEFT_AUTO_FINAL\rebuild_workspace")
OUT = L.out_dir("H01")
GATE = OUT / "zancudo_gate"
FLAG = L.FLAGS["H01"]
BANNER = "ZANCUDO DEADBOLT RELEASED"


def wsl_path(p) -> str:
    s = str(p).replace("\\", "/")
    return "/mnt/" + s[0].lower() + s[2:]


def run_py(script: str):
    return subprocess.run([sys.executable, str(WS / script)],
                          capture_output=True, text=True)


def run_gate(arg: str):
    return subprocess.run(
        ["wsl.exe", "-e", "bash", "-lc", f"'{wsl_path(GATE)}' '{arg}'"],
        capture_output=True, text=True)


def main():
    # 1. build
    b = run_py("gen_h01.py")
    assert b.returncode == 0 and "BUILD_OK" in b.stdout, b.stdout + b.stderr
    assert GATE.exists(), GATE
    print("[H01] build OK")

    # 2. solver
    s = run_py("solve_h01.py")
    assert s.returncode == 0 and f"[H01] PASS -> {FLAG}" in s.stdout, s.stdout + s.stderr
    print(f"[H01] solver PASS -> {FLAG}")

    # 3. correct passphrase accepted
    good = run_gate(FLAG)
    assert good.returncode == 0 and BANNER in good.stdout, (good.returncode, good.stdout)
    print("[H01] correct passphrase accepted (exit 0)")

    # 4. wrong passphrases rejected
    wrongs = [
        "FTA{wrong_passphrase_0000000000}",
        FLAG[:-1] + "x",                    # same length, last byte flipped
        FLAG.replace("unl0ck", "un10ck"),   # single-character mutation
        "zancudo",
    ]
    for w in wrongs:
        r = run_gate(w)
        assert r.returncode != 0 and BANNER not in r.stdout, (w, r.returncode, r.stdout)
    print(f"[H01] wrong passphrases rejected ({len(wrongs)})")

    # 5. no plaintext flag in participant artifacts
    for f in sorted(OUT.iterdir()):
        if f.is_file():
            assert FLAG.encode() not in f.read_bytes(), f"flag leaked in {f.name}"
    st = subprocess.run(
        ["wsl.exe", "-e", "bash", "-lc",
         f"strings -a '{wsl_path(GATE)}' | grep -c FTA || true"],
        capture_output=True, text=True)
    assert st.stdout.strip() == "0", st.stdout
    print("[H01] strings: no plaintext flag in ELF (0 FTA hits)")

    print("[H01] VALIDATE OK")


if __name__ == "__main__":
    main()
