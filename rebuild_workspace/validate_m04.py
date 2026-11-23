#!/usr/bin/env python3
"""M04 - Underground XOR Radio. Validator (private).

  1. Runs the reference solver end to end and checks it prints PASS + the
     canonical flag.
  2. Asserts a WRONG flag is rejected: corrupt one ciphertext byte inside the
     flag region and confirm the decoded payload no longer matches (and that
     the solver's equality guard would fire).
"""
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
import solve_m04 as S


def decode(packet: bytes) -> bytes:
    out = L.out_dir("M04")
    sample = (out / "keystream_sample.bin").read_bytes()
    exposed = bytes(s ^ h for s, h in zip(sample, S.HEADER.encode()))
    bits = S.bytes_to_bits(exposed)
    C, deg = S.berlekamp_massey(bits)
    full = S.bits_to_bytes(S.extend(bits, C, deg, len(packet) * 8))
    return bytes(p ^ k for p, k in zip(packet, full))


def main():
    here = Path(__file__).resolve().parent

    # 1. run the solver as a fresh process
    r = subprocess.run([sys.executable, str(here / "solve_m04.py")],
                       capture_output=True, text=True)
    assert r.returncode == 0, f"solver exited {r.returncode}\n{r.stderr}"
    expected = f"[M04] PASS -> {L.FLAGS['M04']}"
    assert expected in r.stdout, f"solver stdout: {r.stdout!r}"
    print(r.stdout.strip())

    # 2. wrong-flag rejection
    out = L.out_dir("M04")
    packet = (out / "radio_packet.bin").read_bytes()
    pt = decode(packet)
    off = pt.index(b"FTA{")
    good = re.search(rb"FTA\{[^}]+\}", pt).group(0).decode()
    assert good == L.FLAGS["M04"], good

    bad = bytearray(packet)
    bad[off + 6] ^= 0x01                  # corrupt one byte inside the flag body
    m = re.search(rb"FTA\{[^}]+\}", decode(bytes(bad)))
    assert m, "no flag after corruption"
    wrong = m.group(0).decode()
    assert wrong != L.FLAGS["M04"], "wrong flag was NOT rejected"

    try:
        assert wrong == L.FLAGS["M04"]
        raise SystemExit("FAIL: guard accepted a wrong flag")
    except AssertionError:
        pass

    print(f"[M04] VALIDATE OK (good={good!r}, wrong rejected={wrong!r})")


if __name__ == "__main__":
    main()
