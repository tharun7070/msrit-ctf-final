#!/usr/bin/env python3
"""M08 validation harness.

Checks:
  1. solve_m08.py runs to completion and prints ``[M08] PASS -> <flag>``.
  2. The genuine C2 flow decrypts to the Part-3 flag.
  3. Negative tests: a wrong session id authenticates nothing; the decoy flow
     never authenticates under the live session id; ignoring the MAC chaining
     yields garbage; a corrupted exfil frame is rejected by its HMAC tag; the
     planted bait flag never appears in any genuine decrypted payload.
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import lib_fta as L
import solve_m07
import solve_m08

M08_DIR = L.out_dir("M08")
BAIT = b"FTA{n1ghtsh1ft_c2_s3ss10n_b41t_d0_n0t_subm1t}"


def main():
    expected = L.FLAGS["M08"]

    # 1. solver runs cleanly
    r = subprocess.run([sys.executable, str(HERE / "solve_m08.py")],
                       cwd=str(HERE), capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "[M08] PASS -> " + expected in r.stdout, r.stdout
    print("[validate] solver OK:", r.stdout.strip())

    # 2. genuine flow decrypts to the flag
    _, _host, port, sid = solve_m07.recover()
    pcap = M08_DIR / "nightshift_c2.pcap"
    blobs = list(solve_m08.flows(pcap))
    genuine = [b for (_s, _d, _sp, dp, b) in blobs if dp == port]
    other = [b for (_s, _d, _sp, dp, b) in blobs if dp != port]
    assert genuine and other, (genuine, other)
    joint = b"".join(solve_m08.walk_chain(sid, solve_m08.parse_frames(genuine[0])))
    assert expected.encode() in joint, joint
    print("[validate] genuine flow recovered %s:%d" % (_host, port))

    # 3a. a wrong session id authenticates nothing
    zero = b"".join(solve_m08.walk_chain(b"\x00" * 16,
                                         solve_m08.parse_frames(genuine[0])))
    assert b"FTA{" not in zero, "wrong sid unexpectedly produced a frame"

    # 3b. the decoy flow never authenticates under the live sid
    for b in other:
        assert b"FTA{" not in b"".join(
            solve_m08.walk_chain(sid, solve_m08.parse_frames(b)))

    # 3c. ignoring the MAC chaining yields garbage, never the flag
    frames = solve_m08.parse_frames(genuine[0])
    valid = sorted((f for f in frames if f["ftype"] != 0x00 and solve_m08.mac_ok(sid, f)),
                   key=lambda f: f["seq"])
    seen, unchained = set(), []
    for fr in valid:
        if fr["seq"] in seen:
            continue
        seen.add(fr["seq"])
        unchained.append(solve_m08.xor_key(
            fr["ct"], solve_m08.keystream(sid, fr["nonce"], fr["seq"], len(fr["ct"]))))
    assert expected.encode() not in b"".join(unchained), "unchained route leaked the flag"

    # 3d. a corrupted exfil frame is rejected by its HMAC tag
    bad = [dict(f) for f in frames]
    last = max(range(len(bad)), key=lambda i: bad[i]["seq"])
    ct = bytearray(bad[last]["ct"])
    ct[0] ^= 0x01
    bad[last]["ct"] = bytes(ct)
    assert not solve_m08.mac_ok(sid, bad[last])
    assert expected.encode() not in b"".join(solve_m08.walk_chain(sid, bad))

    # 3e. the planted bait flag never rides in any genuine decrypted payload
    assert BAIT not in joint, "bait flag leaked into the genuine flow"

    print("[validate] negative routes rejected")
    print("[validate] M08 VALIDATE OK (flag=%s)" % expected)


if __name__ == "__main__":
    main()
