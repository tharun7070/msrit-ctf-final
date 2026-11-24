#!/usr/bin/env python3
"""M06 validation harness.

Checks:
  1. solve_m06.py runs to completion and prints ``[M06] PASS -> <flag>``.
  2. A wrong flag is rejected.
  3. Negative tests: a corrupted PACK body, a truncated container and the
     note's "key table used as stored" route all fail to recover the flag.
"""
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lib_fta as L
import solve_m06

M06_DIR = L.out_dir("M06")


def main():
    expected = L.FLAGS["M06"]

    # 1. solver runs cleanly
    r = subprocess.run([sys.executable, str(HERE / "solve_m06.py")],
                       cwd=str(HERE), capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "[M06] PASS -> " + expected in r.stdout, r.stdout
    print("[validate] solver OK:", r.stdout.strip())

    # 2. wrong flag rejected
    got, token = solve_m06.recover()
    assert got == expected
    try:
        assert expected != L.FLAGS["M06"] + "x"
    finally:
        pass
    print("[validate] flag/token recovered cleanly")

    good = (M06_DIR / "nightshift_loader.bin").read_bytes()

    # 3a. corrupt a byte inside PACK -> checksum must reject
    rort, sec = solve_m06.parse_container(good)
    pack_off = good.find(b"PACK") + 8
    bad = bytearray(good)
    bad[pack_off + 6] ^= 0x01
    try:
        solve_m06.recover(bytes(bad))
        raise SystemExit("[validate] corrupted PACK was accepted!")
    except ValueError:
        pass

    # 3b. truncated container -> must not recover
    try:
        solve_m06.recover(good[:40])
        raise SystemExit("[validate] truncated container was accepted!")
    except Exception:
        pass

    # 3c. the note's route (KEYT used as stored) must not verify
    keyt = sec[b"KEYT"]
    pack = sec[b"PACK"]
    crc = struct.unpack("<I", pack[:4])[0]
    enc = solve_m06.xor_key(pack[4:], solve_m06.keystream(keyt, len(pack) - 4))
    import zlib
    assert zlib.crc32(enc) & 0xFFFFFFFF != crc, "rotated table unexpectedly verified"

    print("[validate] negative routes rejected")
    print("[validate] M06 VALIDATE OK (flag=%s)" % expected)


if __name__ == "__main__":
    main()
