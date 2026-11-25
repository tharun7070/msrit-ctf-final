#!/usr/bin/env python3
"""M05 validation harness.

Checks:
  1. solve_m05.py runs to completion and prints ``[M05] PASS -> <flag>``.
  2. A wrong flag is rejected by the solver's verification.
  3. broken_dispatch.py is *reliably* wrong: run in an isolated temp copy
     several times and confirm it never reproduces the correct out.bin.
  4. The two-run requirement: the flag needs BOTH lane payloads combined.
  5. The traps are present: a partial fix falls through to ARCHIVED_VALUE plus a
     well-formed decoy flag blob; recovery_note.txt advertises a wrong method
     and carries a decoy flag; the manifest notes carry a decoy.
  6. The real flag never appears in any shipped artifact; the payload stays
     modest (< 2 MB).
"""
import base64
import json
import re
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
ARTIFACTS = ("broken_dispatch.py", "dispatch_packets.json", "README.txt",
             "recovery_note.txt")
FTA_RE = re.compile(r"FTA\{[a-z0-9_]+\}")
PACKET_COUNT = 1200


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

    # reference data from the repaired pipeline
    ref = solve_m05.recover()
    correct_s2 = ref["stage2_src"].encode()
    key, R0, R1 = ref["key"], ref["R0"], ref["R1"]

    # 3. broken dispatcher is reliably wrong
    wrong = 0
    for _ in range(RUNS):
        with tempfile.TemporaryDirectory() as td:
            shutil.copy(M05_DIR / "broken_dispatch.py", td)
            shutil.copy(M05_DIR / "dispatch_packets.json", td)
            rr = subprocess.run([sys.executable, str(Path(td) / "broken_dispatch.py")],
                                cwd=td, capture_output=True, text=True)
            assert rr.returncode == 0, rr.stderr
            man = _manifest((Path(td) / "out.bin").read_bytes())
            src = base64.b64decode(man["stage2_b64"])
            if man["dispatched"] != PACKET_COUNT or src != correct_s2:
                wrong += 1
    assert wrong == RUNS, "race not reliably visible: %d/%d" % (wrong, RUNS)
    print("[validate] broken_dispatch wrong in %d/%d runs" % (wrong, RUNS))

    # 4. two-run requirement: neither lane alone yields the flag.  Feeding the
    # same lane twice XORs to zero (or a single stream), which the later stages
    # either reject outright or decode to structurally valid garbage - never the
    # flag.
    flagb = expected.encode()

    def _peel_or_none(a: bytes, b: bytes):
        try:
            return solve_m05.assemble_peel(a, b, key)
        except Exception:
            return None

    assert solve_m05.assemble_peel(R0, R1, key) == flagb
    assert R0 != R1
    assert _peel_or_none(R0, R0) != flagb
    assert _peel_or_none(R1, R1) != flagb
    print("[validate] both lane runs required for the flag")

    # 5a. partial fix -> shipped stage-2 falls to ARCHIVED_VALUE + decoy flag blob
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "stage2.py"
        p.write_text(ref["stage2_src"], encoding="utf-8")
        rr = subprocess.run([sys.executable, str(p)], cwd=td,
                            capture_output=True, text=True)
        assert rr.returncode == 0, rr.stderr
        lines = [ln for ln in rr.stdout.splitlines() if ln.strip()]
        assert not any(ln.startswith("R0=") for ln in lines), \
            "shipped stage-2 unexpectedly succeeded"
        assert lines[0] == ref["ns"]["ARCHIVED_VALUE"]
        fake = base64.b64decode(lines[1]).decode("ascii")
        assert FTA_RE.fullmatch(fake), "reward blob is not a well-formed flag"
        assert fake != expected
    print("[validate] partial fix lands on ARCHIVED_VALUE + decoy flag")

    # 5b. recovery_note.txt advertises a wrong method and carries a decoy flag
    note = (M05_DIR / "recovery_note.txt").read_text(encoding="utf-8")
    note_flags = FTA_RE.findall(note)
    assert note_flags and all(f != expected for f in note_flags), note_flags
    assert "archived" in note.lower()
    low = note.lower()
    assert ("single pass" in low) or ("one pass" in low) or ("once" in low)

    # 5c. the manifest / node notes carry a decoy
    bd_text = (M05_DIR / "broken_dispatch.py").read_text(encoding="utf-8")
    notes_flags = FTA_RE.findall(bd_text)
    assert notes_flags and all(f != expected for f in notes_flags), notes_flags
    print("[validate] traps present (note + notes + reward decoys)")

    # 6. real flag never appears in any shipped artifact
    for name in ARTIFACTS:
        txt = (M05_DIR / name).read_text(encoding="utf-8")
        assert expected not in txt, name
    assert expected.encode() not in correct_s2
    print("[validate] real flag absent from every artifact")

    total = sum((M05_DIR / n).stat().st_size for n in ARTIFACTS)
    assert total < 2 * 1024 * 1024, total
    print("[validate] artifacts total %d bytes" % total)

    print("[validate] M05 VALIDATE OK (flag=%s)" % expected)


if __name__ == "__main__":
    main()
