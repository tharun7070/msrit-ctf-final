#!/usr/bin/env python3
"""M04 - Underground XOR Radio. Validator (private).

  1. Runs the reference solver end to end and checks it prints PASS + the
     canonical flag.
  2. Asserts a WRONG flag is rejected: corrupt one ciphertext byte that maps
     (through the lane transpose) onto a byte inside the flag body, and confirm
     the decoded payload no longer matches (and that the solver's equality
     guard would fire).

decode() re-derives the plaintext from radio_packet.bin using the same public
helpers exported by solve_m04 (S.HEADER, S.bytes_to_bits, S.berlekamp_massey,
S.extend, S.bits_to_bytes, S.unpermute).
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

    # unmask the surviving header prefix -> exposed mask bytes
    exposed = bytes(s ^ h for s, h in zip(sample, S.HEADER))[:S.REDACT_FROM]
    lane_a = exposed[0::2]
    lane_b = exposed[1::2]
    a_bits = S.bytes_to_bits(lane_a)
    b_bits = S.bytes_to_bits(lane_b)
    Ca, da = S.berlekamp_massey(a_bits)
    Cb, db = S.berlekamp_massey(b_bits)

    n = len(packet)
    a = S.bits_to_bytes(S.extend(a_bits, Ca, da, ((n + 1) // 2) * 8))
    b = S.bits_to_bytes(S.extend(b_bits, Cb, db, (n // 2) * 8))
    mask = bytes(a[j // 2] if j % 2 == 0 else b[j // 2] for j in range(n))

    masked = S.unpermute(packet)               # undo the lane transpose first
    return bytes(p ^ k for p, k in zip(masked, mask))


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

    # map the plaintext offset of a flag-body byte back to its packet index
    perm = S.permutation(len(packet))         # payload[perm[p]] == masked[p]
    bad = bytearray(packet)
    bad[perm[off + 6]] ^= 0x01                # corrupt inside the flag body
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
