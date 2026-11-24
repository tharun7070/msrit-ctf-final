#!/usr/bin/env python3
"""E12 - Relay Archive. Validator (private).

  1. Runs solve_e12.py as a fresh subprocess and checks it prints exactly the
     canonical PASS line.
  2. NEGATIVE #1 - every single-carrier (legacy replay) parcel must NOT yield
     the real flag.
  3. NEGATIVE #2 - a wrong session key must fail to inflate the real flag.
  4. NEGATIVE #3 - a parcel missing a fragment must not reassemble.
  5. CHAIN - the genuine archive tag must equal the live Ghost Relay (E11) tag.
"""
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "relay"))
import lib_fta as L            # noqa: E402
import relay_proto as P        # noqa: E402
import solve_e12 as S          # noqa: E402


def _flags_from(text):
    return set(re.findall(r"FTA\{[a-z0-9_]+\}", text))


def main():
    here = Path(__file__).resolve().parent
    real = L.FLAGS["E12"]

    r = subprocess.run([sys.executable, str(here / "solve_e12.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"solver exited {r.returncode}\n{r.stderr}"
    expected = f"[E12] PASS -> {real}"
    assert r.stdout.strip() == expected, f"solver stdout: {r.stdout!r}"
    print(r.stdout.strip())

    frames = P.parse_pcap((L.out_dir("E12") / "relay_archive.pcap").read_bytes())
    sessions = S.group(frames)
    dual = {P.PORT_DATA_A, P.PORT_DATA_B}

    # 2. single-carrier legacy replays must not carry the REAL flag -----------
    stamped = set()
    for sess, ent in sessions.items():
        if set(dual) <= ent["carriers"]:
            continue
        try:
            stamped |= _flags_from(P.decode_drop(ent["ctrl"], ent["frags"]))
        except Exception:  # noqa: BLE001
            pass
    assert stamped, "no legacy replay parcel produced a flag"
    assert real not in stamped, f"a legacy replay yielded the REAL flag: {stamped}"
    print(f"[E12] legacy replays -> {sorted(stamped)} (not the real flag)")

    # 3. wrong key rejected ----------------------------------------------------
    gen = next(e for s, e in sessions.items() if set(dual) <= e["carriers"])
    good_key = P.key_from_fragment(gen["ctrl"])
    assert P.decode_drop(gen["ctrl"], gen["frags"]) == real
    bad_key = bytes([good_key[0] ^ 0x01]) + good_key[1:]
    wrong = None
    try:
        wrong = P.decode_drop(P.key_fragment(bad_key), gen["frags"])
    except Exception:  # noqa: BLE001
        wrong = None
    assert wrong is None or _flags_from(wrong) != {real}, \
        f"a wrong key still produced the real flag: {wrong!r}"
    print(f"[E12] corrupt key 0x{good_key.hex()} -> 0x{bad_key.hex()} rejected")

    # 4. dropped fragment must not reassemble ----------------------------------
    partial = dict(gen["frags"])
    del partial[min(partial)]
    lost = None
    try:
        lost = P.decode_drop(gen["ctrl"], partial)
    except Exception:  # noqa: BLE001
        lost = None
    assert lost is None or _flags_from(lost) != {real}, \
        f"a truncated parcel still produced the real flag: {lost!r}"
    print("[E12] missing fragment -> parcel does not reassemble")

    # 5. the chain: archive tag == Ghost Relay (E11) capture tag ----------------
    live = S.live_tag()
    tag = next(s for s, e in sessions.items() if set(dual) <= e["carriers"])
    assert live is not None and tag == live, \
        f"archive tag 0x{tag:04X} != Ghost Relay tag {live}"
    print(f"[E12] archive tag 0x{tag:04X} == Ghost Relay tag 0x{live:04X}")

    print("[E12] VALIDATE OK")


if __name__ == "__main__":
    main()
