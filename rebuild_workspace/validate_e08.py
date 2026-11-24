#!/usr/bin/env python3
"""E08 - Dead Drop Uplink. Validator (private).

  1. Runs solve_e08.py as a fresh subprocess and checks it prints exactly the
     canonical PASS line.
  2. NEGATIVE #1 - the DECOY session (magic 0xD1E0) reassembles to a decoy
     flag and must NOT yield the real flag.
  3. NEGATIVE #2 - a wrong session key must fail to inflate into the real flag.
  4. NEGATIVE #3 - a session missing a fragment must not reassemble the flag.
"""
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
import solve_e08 as S


def _flags_from(text):
    return set(re.findall(r"FTA\{[a-z0-9_]+\}", text))


def main():
    here = Path(__file__).resolve().parent
    real = L.FLAGS["E08"]

    # 1. positive: run the reference solver as a fresh process -----------------
    r = subprocess.run([sys.executable, str(here / "solve_e08.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"solver exited {r.returncode}\n{r.stderr}"
    expected = f"[E08] PASS -> {real}"
    assert r.stdout.strip() == expected, f"solver stdout: {r.stdout!r}"
    print(r.stdout.strip())

    out = L.out_dir("E08")
    frames = S.parse_pcap((out / "dead_drop.pcap").read_bytes())

    # 2. negative: decoy session must not carry the REAL flag ------------------
    decoy = S.collect(frames, S.MAGIC_DECOY)
    assert decoy, "no decoy session found in the capture"
    decoy_flags = set()
    for ent in decoy.values():
        if ent["ctrl"] is None:
            continue
        try:
            decoy_flags |= _flags_from(S.decode_session(ent["ctrl"], ent["frags"]))
        except Exception:
            pass
    assert decoy_flags, "decoy session produced no flag"
    assert real not in decoy_flags, f"decoy session yielded the REAL flag: {decoy_flags}"
    print(f"[E08] decoy session -> {sorted(decoy_flags)} (not the real flag)")

    # 3. negative: a wrong session key must fail -------------------------------
    genuine = S.collect(frames, S.MAGIC_GENUINE)
    session, ent = next(((s, e) for s, e in genuine.items() if e["ctrl"]),
                        (None, None))
    assert ent is not None, "genuine CONTROL packet missing"
    good_key = S.key_from_fragment(ent["ctrl"])
    assert S.decode_session(ent["ctrl"], ent["frags"]) == real

    bad_key = bytes([good_key[0] ^ 0x01]) + good_key[1:]
    wrong = None
    try:
        wrong = S.decode_session(S.encode_key_fragment(bad_key), ent["frags"])
    except Exception:
        wrong = None
    assert wrong is None or _flags_from(wrong) != {real}, \
        f"a wrong key still produced the real flag: {wrong!r}"
    print(f"[E08] corrupt key 0x{good_key.hex()} -> 0x{bad_key.hex()} rejected")

    # 4. negative: a dropped fragment must not reassemble ----------------------
    partial = dict(ent["frags"])
    del partial[min(partial)]
    lost = None
    try:
        lost = S.decode_session(ent["ctrl"], partial)
    except Exception:
        lost = None
    assert lost is None or _flags_from(lost) != {real}, \
        f"a truncated session still produced the real flag: {lost!r}"
    print("[E08] missing fragment -> session does not reassemble")

    print("[E08] VALIDATE OK")


if __name__ == "__main__":
    main()
