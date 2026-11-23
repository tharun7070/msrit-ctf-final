#!/usr/bin/env python3
"""H04 reference solver - RSA-CRT fault attack + admin token forgery.

Steps:
  1. Ask the debug route for the SAME reference message a few times; grab one
     correct signature and one faulty signature.
  2. A faulty RSA-CRT signature differs from the true one modulo only ONE of
     the two prime factors, so gcd((bad^e - m) mod n, n) exposes a factor of n.
  3. Factor n, rebuild the private exponent, sign the admin vault order and
     present it to the gateway to unlock the flag.
"""
import math
import os
import sys
from pathlib import Path

sys.path.insert(0, r"d:\ctf\FLAG_THEFT_AUTO_FINAL\rebuild_workspace")
import lib_fta as L

OUT = L.out_dir("H04")
sys.path.insert(0, str(OUT))
os.environ["FTA_H04_FLAG"] = L.FLAGS["H04"]
import bank_gateway as gw  # noqa: E402


def solve():
    n, e = gw.public_params()

    probe = b"REF:probe:balance:0001"
    m = int.from_bytes(probe, "big")
    assert m < n

    good = bad = None
    bad_seed = good_seed = None
    for seed in range(20000):
        r = gw.sign_debug(probe, seed)
        if r["fault"] and bad is None:
            bad, bad_seed = int(r["signature"], 16), seed
        if not r["fault"] and good is None:
            good, good_seed = int(r["signature"], 16), seed
        if bad is not None and good is not None:
            break
    assert bad is not None and good is not None, "could not obtain both signatures"

    # Sanity: the non-faulty answer really is a valid signature of the probe.
    assert pow(good, e, n) == m % n, "correct signature does not verify"

    # Fault attack: the faulty answer still holds modulo the untouched factor,
    # so n and (bad^e - m) share exactly that factor.
    p = math.gcd((pow(bad, e, n) - m) % n, n)
    assert 1 < p < n, "fault attack failed to split n (no factor recovered)"
    q = n // p
    assert p * q == n
    if p < q:
        p, q = q, p
    assert L.egcd(e, (p - 1) * (q - 1))[0] == 1

    d = L.modinv(e, (p - 1) * (q - 1))

    # Forge a correctly-signed ADMIN vault order.
    admin_int = int.from_bytes(gw.ADMIN_MESSAGE.encode(), "big")
    forged_sig = pow(admin_int, d, n)
    token = {"role": "admin", "msg": gw.ADMIN_MESSAGE, "sig": format(forged_sig, "x")}

    # Secondary confirmation: the non-constant-time verifier accepts it.
    assert gw.verify(token) is True, "forged token failed verification"

    flag = gw.submit(token)
    assert flag == L.FLAGS["H04"], flag

    print("[H04] recovered factor p =", p)
    print("[H04] cofactor      q =", q)
    print("[H04] faulty half     =", gw.sign_debug(probe, bad_seed)["half"])
    print("[H04] forged admin token accepted; flag unlocked")
    print("[H04] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
