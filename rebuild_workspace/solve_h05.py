#!/usr/bin/env python3
"""H05 - "Last Ride Out" reference solver.

Reads the captured ESCAPE-3 handshake (`intercept.bin`), identifies the three
parties' contributions from the TLV type codes, notices that C's contribution
(0x0012) carries no binding tag and is advertised TWICE, adopts the most recent
one (the injected share) exactly as the protocol says, rebuilds the session key
from the transcript, checks it against the key-confirmation tag, and opens
`final_payload.enc` (AES-256-GCM, nonce prepended).

The key insight: because C's word is taken on trust and may be re-advertised,
the key that actually sealed the payload is the one built from the *injected*
C share - and every input to that key is public in the transcript.
"""
import hashlib, hmac, sys
from Crypto.Cipher import AES

sys.path.insert(0, r"d:\ctf\FLAG_THEFT_AUTO_FINAL\rebuild_workspace")
import lib_fta as L

LABEL = b"ESCAPE-3/session-key/v1"

T_SID = 0x0002
T_A_SHARE, T_B_SHARE, T_C_SHARE = 0x0010, 0x0011, 0x0012
T_CONFIRM = 0x0020


def load_transcript():
    raw = (L.out_dir("H05") / "intercept.bin").read_bytes()
    recs = L.read_tlvs(raw)
    sid = None
    a_shares, b_shares, c_shares = [], [], []
    confirm = None
    for typ, val in recs:
        if typ == T_SID:
            sid = val
        elif typ == T_A_SHARE:
            a_shares.append(val)
        elif typ == T_B_SHARE:
            b_shares.append(val)
        elif typ == T_C_SHARE:
            c_shares.append(val)
        elif typ == T_CONFIRM:
            confirm = val
    assert sid is not None and confirm is not None
    assert len(a_shares) == 1 and len(b_shares) == 1
    assert len(c_shares) >= 1, "no C contribution"
    # structural check from the framing: A and B append a 16-byte binding tag,
    # C does not. This is what makes C's word unauthenticated.
    assert len(a_shares[0]) == 48 and len(b_shares[0]) == 48
    assert all(len(v) == 32 for v in c_shares)
    return sid, a_shares[0], b_shares[0], c_shares, confirm


def kdf(sid, xa, xb, xc):
    return hashlib.sha256(LABEL + sid + xa + xb + xc).digest()


def confirm_tag(K, sid, xa, xb, xc):
    return hmac.new(K, b"ESCAPE-3/confirm/v1" + sid + xa + xb + xc,
                    hashlib.sha256).digest()[:16]


def decrypt_payload(K, blob=None):
    if blob is None:
        blob = (L.out_dir("H05") / "final_payload.enc").read_bytes()
    nonce, body = blob[:12], blob[12:]
    ct, tag = body[:-16], body[-16:]
    return AES.new(K, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)


def solve():
    sid, a_val, b_val, c_shares, confirm = load_transcript()
    XA, XB = a_val[:32], b_val[:32]

    # C's contribution is taken verbatim from the transcript and, when it is
    # advertised more than once, the most recent advertisement wins. Adopt it
    # (it is the attacker-forged share that biases the derived key).
    XC_forged = c_shares[-1]

    K = kdf(sid, XA, XB, XC_forged)

    # confirm the key against the handshake's own key-confirmation tag
    assert confirm_tag(K, sid, XA, XB, XC_forged) == confirm, \
        "derived key does not match the confirmation tag"

    pt = decrypt_payload(K).decode()
    flag = pt.split("flag=")[1].splitlines()[0].strip()
    assert flag == L.FLAGS["H05"], flag
    print("[H05] PASS ->", flag)
    return flag


def derive_with_share(share_bytes):
    """Derive a key using a caller-supplied C share (used to prove the wrong
    share fails)."""
    sid, a_val, b_val, _c, _conf = load_transcript()
    return kdf(sid, a_val[:32], b_val[:32], share_bytes)


if __name__ == "__main__":
    solve()
