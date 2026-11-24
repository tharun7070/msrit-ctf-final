#!/usr/bin/env python3
"""H04 reference solver - hardened RSA-CRT fault attack + two-part oracle.

Steps:
  0. The debug signing route BLINDS every request: it signs (m * r^e) and
     hands back the blinding factor r.  So first un-blind every answer:
     sig_real = sig_blind * r^-1 mod n.  A naive gcd(sig^e - m, n) on the raw
     answer finds nothing.
  1. Ask sign_debug for the SAME reference message until we hold one correct
     and one faulty (un-blinded) signature.  The fault rate is low, so many
     probes are needed.
  2. The fault can land in EITHER CRT half, so gcd((bad^e - m) mod n, n) may
     return p OR q; accept whichever prime it yields and validate p*q == n.
  3. Use the quiet verify_debug oracle (leading-byte match count) to recover
     the live per-process audit nonce one byte at a time.
  4. Factor n, rebuild d, assemble the admin vault order from its fields with
     the recovered nonce, sign it, attach the nonce and a fresh timestamp, and
     submit.  The verifier's role/nonce/freshness gates must all pass.
"""
import math
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, r"d:\ctf\FLAG_THEFT_AUTO_FINAL\rebuild_workspace")
import lib_fta as L

OUT = L.out_dir("H04")
sys.path.insert(0, str(OUT))
os.environ["FTA_H04_FLAG"] = L.FLAGS["H04"]
import bank_gateway as gw  # noqa: E402

GUARD_LEN = 6


def recover_nonce():
    """Recover the live audit nonce via the leading-byte match oracle."""
    known = bytearray()
    for i in range(GUARD_LEN):
        for b in range(256):
            cand = bytes(known) + bytes([b]) + bytes(GUARD_LEN - len(known) - 1)
            if gw.verify_debug(cand.hex())["match"] == i + 1:
                known.append(b)
                break
        else:
            raise RuntimeError("nonce oracle failed at byte %d" % i)
    return bytes(known).hex()


def collect_signatures(n):
    """Un-blind debug answers until we have one correct and one faulty."""
    probe = b"REF:probe:balance:0001"
    m = int.from_bytes(probe, "big")
    assert m < n
    good = bad = None
    bad_seed = None
    for seed in range(200000):
        r = gw.sign_debug(probe, seed)
        # Un-blind: sig_blind = m_blind^d = m^d * r  =>  sig = sig_blind * r^-1.
        unblinded = (int(r["signature"], 16) * pow(int(r["blind"], 16), -1, n)) % n
        if r["fault"] and bad is None:
            bad, bad_seed = unblinded, seed
        elif not r["fault"] and good is None:
            good = unblinded
        if good is not None and bad is not None:
            break
    assert good is not None and bad is not None, "could not obtain both signatures"
    return probe, m, good, bad, bad_seed


def solve():
    n, e = gw.public_params()

    probe, m, good, bad, bad_seed = collect_signatures(n)

    # Sanity: after un-blinding, the non-faulty answer is a valid signature.
    assert pow(good, e, n) == m % n, "un-blinded correct signature does not verify"

    # Fault attack: the faulty answer still holds modulo the untouched factor,
    # so n and (bad^e - m) share exactly ONE prime factor (p or q - either).
    g = math.gcd((pow(bad, e, n) - m) % n, n)
    assert 1 < g < n, "fault attack failed to split n (no factor recovered)"
    p, q = g, n // g
    assert p * q == n, "recovered factors do not multiply back to n"
    if p < q:
        p, q = q, p
    assert L.egcd(e, (p - 1) * (q - 1))[0] == 1

    d = L.modinv(e, (p - 1) * (q - 1))

    # Recover the live audit nonce through the second oracle.
    nonce = recover_nonce()

    # Assemble the admin vault order from its fields (static part + live nonce).
    msg = gw.ADMIN_MESSAGE.replace("__NONCE__", nonce)
    forged_sig = pow(int.from_bytes(msg.encode(), "big"), d, n)
    token = {"role": "admin", "msg": msg, "sig": format(forged_sig, "x"),
             "nonce": nonce, "ts": int(time.time())}

    # Secondary confirmation: the non-constant-time verifier accepts it.
    assert gw.verify(token) is True, "forged token failed verification"

    # The pinned decoy verifies but must be refused by the full submit gate.
    assert gw.verify(gw.DECOY_TOKEN) is True, "decoy should verify under naive reading"
    assert gw.submit(gw.DECOY_TOKEN) is None, "decoy must be rejected"

    flag = gw.submit(token)
    assert flag == L.FLAGS["H04"], flag

    print("[H04] recovered factor p =", p)
    print("[H04] cofactor      q =", q)
    print("[H04] faulty half     =", gw.sign_debug(probe, bad_seed)["half"])
    print("[H04] audit nonce     =", nonce)
    print("[H04] forged admin token accepted; flag unlocked")
    print("[H04] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
