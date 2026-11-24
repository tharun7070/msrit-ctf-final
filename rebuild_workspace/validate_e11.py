#!/usr/bin/env python3
"""E11 - Ghost Relay. Validator (private).

  1. Runs solve_e11.py as a fresh subprocess and checks it prints exactly the
     canonical PASS line.
  2. NEGATIVE #1 - the DECOY burst (magic 0xCB02 on udp/7003) must NOT yield
     the real flag.
  3. NEGATIVE #2 - a wrong session key must fail to inflate the real flag.
  4. NEGATIVE #3 - a drop missing a fragment must not reassemble the flag.
"""
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "relay"))
import lib_fta as L            # noqa: E402
import relay_proto as P        # noqa: E402
import solve_e11 as S          # noqa: E402


def _flags_from(text):
    return set(re.findall(r"FTA\{[a-z0-9_]+\}", text))


def main():
    here = Path(__file__).resolve().parent
    real = L.FLAGS["E11"]

    r = subprocess.run([sys.executable, str(here / "solve_e11.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"solver exited {r.returncode}\n{r.stderr}"
    expected = f"[E11] PASS -> {real}"
    assert r.stdout.strip() == expected, f"solver stdout: {r.stdout!r}"
    print(r.stdout.strip())

    frames = P.parse_pcap((L.out_dir("E11") / "ghost_relay.pcap").read_bytes())

    # 2. decoy burst must not carry the REAL flag ------------------------------
    dctrl, dseqs = S.collect(frames, P.FRAME_MAGIC_DECOY, P.SESSION_DECOY)
    assert dctrl is not None, "no decoy CONTROL frame found"
    decoy_flag = P.decode_drop(dctrl, dseqs)
    assert _flags_from(decoy_flag) and real not in _flags_from(decoy_flag), \
        f"decoy burst yielded the REAL flag: {decoy_flag}"
    print(f"[E11] decoy relay -> {decoy_flag} (not the real flag)")

    # 3. a wrong session key must fail ----------------------------------------
    ctrl, seqs = S.collect(frames, P.FRAME_MAGIC_GENUINE, P.SESSION_E11)
    good_key = P.key_from_fragment(ctrl)
    assert P.decode_drop(ctrl, seqs) == real
    bad_key = bytes([good_key[0] ^ 0x01]) + good_key[1:]
    wrong = None
    try:
        wrong = P.decode_drop(P.key_fragment(bad_key), seqs)
    except Exception:  # noqa: BLE001
        wrong = None
    assert wrong is None or _flags_from(wrong) != {real}, \
        f"a wrong key still produced the real flag: {wrong!r}"
    print(f"[E11] corrupt key 0x{good_key.hex()} -> 0x{bad_key.hex()} rejected")

    # 4. a dropped fragment must not reassemble -------------------------------
    partial = dict(seqs)
    del partial[min(partial)]
    lost = None
    try:
        lost = P.decode_drop(ctrl, partial)
    except Exception:  # noqa: BLE001
        lost = None
    assert lost is None or _flags_from(lost) != {real}, \
        f"a truncated drop still produced the real flag: {lost!r}"
    print("[E11] missing fragment -> drop does not reassemble")

    print("[E11] VALIDATE OK")


if __name__ == "__main__":
    main()
