#!/usr/bin/env python3
"""M04 - Underground XOR Radio. Validator (private).

  1. Runs the reference solver end to end and checks it prints PASS + the
     canonical flag.
  2. Asserts a WRONG flag is rejected: corrupt one ciphertext byte that maps
     (through the lane transpose) onto a byte inside the flag body, and confirm
     the decoded payload no longer matches.
  3. Asserts the ROUND-ROBIN STARTING LANE actually matters: decoding with a
     different (wrong) lane offset must NOT recover the flag, since it re-groups
     the sample bytes into mixed register streams.

decode() re-derives the plaintext from radio_packet.bin using the public
helpers exported by solve_m04 (S.parse_header, S.recover_mask, S.unpermute,
S.permutation, ...). decode(..., force_off=o) optionally forces a lane offset
to exercise the offset trap.
"""
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L
import solve_m04 as S


def decode(packet: bytes, force_off=None) -> bytes:
    out = L.out_dir("M04")
    sample = (out / "keystream_sample.bin").read_bytes()

    if force_off is None:
        mask = S.recover_mask(sample, packet, len(packet) - S.HDR_LEN)
    else:
        # deliberately use the wrong lane offset (same demux code path)
        off, burst, bdeg, btaps = S.parse_header(packet)
        exposed = bytes(s ^ h for s, h in
                        zip(sample, S.HEADER))[:S.REDACT_FROM]
        lanes = S.demux(exposed, burst, force_off)
        counts = S.lane_counts(len(packet) - S.HDR_LEN, burst, force_off)
        streams = [None, None, None]
        for r in (0, 1):
            bits = S.bytes_to_bits(bytes(lanes[r]))
            C, dd = S.berlekamp_massey(bits)
            streams[r] = S.bits_to_bytes(S.extend(bits, C, dd, counts[r] * 8))
        known = S.bytes_to_bits(bytes(lanes[S.BEACON]))[:counts[S.BEACON] * 8]
        seed = S.recover_beacon_seed(known, btaps)
        streams[S.BEACON] = L.lfsr_keystream(seed, btaps, counts[S.BEACON])
        mask = S.assign(len(packet) - S.HDR_LEN, streams, burst, force_off)

    ct = packet[S.HDR_LEN:]
    masked = S.unpermute(ct)               # undo the lane transpose first
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

    out = L.out_dir("M04")
    packet = (out / "radio_packet.bin").read_bytes()
    off, burst, bdeg, btaps = S.parse_header(packet)

    pt = decode(packet)
    off_pt = pt.index(b"FTA{")
    good = re.search(rb"FTA\{[^}]+\}", pt).group(0).decode()
    assert good == L.FLAGS["M04"], good

    # 2. wrong-flag rejection: map a flag-body plaintext byte back to its ct index
    perm = S.permutation(len(packet) - S.HDR_LEN)   # ct[perm[p]] == masked[p]
    bad = bytearray(packet)
    bad[S.HDR_LEN + perm[off_pt + 6]] ^= 0x01       # corrupt inside the flag body
    m = re.search(rb"FTA\{[^}]+\}", decode(bytes(bad)))
    assert m, "no flag after corruption"
    wrong = m.group(0).decode()
    assert wrong != L.FLAGS["M04"], "wrong flag was NOT rejected"

    try:
        assert wrong == L.FLAGS["M04"]
        raise SystemExit("FAIL: guard accepted a wrong flag")
    except AssertionError:
        pass

    # 3. the lane offset in the sync header must matter
    other = next(o for o in (0, 1, 2) if o != off)
    bad_mask = decode(packet, force_off=other)
    m2 = re.search(rb"FTA\{[^}]+\}", bad_mask)
    off_ok = (m2 is not None and m2.group(0).decode() == L.FLAGS["M04"])
    assert not off_ok, f"wrong lane offset {other} still decoded the flag"

    print(f"[M04] VALIDATE OK (lane_off={off} burst={burst} "
          f"beacon_deg={bdeg}, good={good!r}, wrong rejected={wrong!r}, "
          f"wrong-offset {other} rejected)")


if __name__ == "__main__":
    main()
