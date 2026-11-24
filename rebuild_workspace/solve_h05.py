#!/usr/bin/env python3
"""H05 - "Last Ride Out" reference solver.

Reads the captured ESCAPE-3 handshake (`intercept.bin`) and performs the
protocol break:

  1. Walk the TLV transcript, ignoring the decoy record types (non-protocol
     codes such as the legacy-share decoy and the extra confirmation records).
  2. Work out, from the framing alone, which contributions are *bound* (a
     48-byte value: 32-byte element plus a 16-byte binding tag) and which are
     *reduced* (a bare 32-byte element).  The reduced contributions are the ones
     the protocol accepts on faith.
  3. Two of the reduced contributions (C and D) are re-advertised; the protocol
     keeps the most recent advertisement of each.
  4. Recompute the weighted-product agreement value
     Y = X_A^3 * X_B^5 * X_C^7 * X_D^11 mod p, run it through the HKDF, and
     check the resulting key against the *real* key-confirmation record.
  5. The payload is double-wrapped: AES-256-GCM (outer) over an
     AES-256-CBC blob (inner).  Decrypt both stages.

The key insight: the reduced-profile contributions are taken on trust, and the
last advertisement of each wins, so the effective key is built entirely from
public transcript material - and the steered C share makes Y land on the value
the payload was sealed under.
"""
import hashlib, hmac, sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

sys.path.insert(0, r"d:\ctf\FLAG_THEFT_AUTO_FINAL\rebuild_workspace")
import lib_fta as L

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

SALT = b"ESCAPE-3/hkdf/salt/v2"
INFO = b"ESCAPE-3/session-key/v2"
CONFIRM_LABEL = b"ESCAPE-3/confirm/v2"
INNER_SALT = b"ESCAPE-3/inner-cbc/v2"
INNER_INFO = b"inner-vault"

ALPHA, BETA, GAMMA, DELTA = 5, 11, 13, 17

T_SID = 0x0002
T_A_SHARE, T_B_SHARE, T_C_SHARE, T_D_SHARE = 0x0010, 0x0011, 0x0012, 0x0013
T_CONFIRM = 0x0020


def _hkdf(salt, ikm, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, ctr = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([ctr]), hashlib.sha256).digest()
        okm += t
        ctr += 1
    return okm[:length]


def _records():
    raw = (L.out_dir("H05") / "intercept.bin").read_bytes()
    return L.read_tlvs(raw)


def load_transcript():
    recs = _records()
    sid = None
    a_shares, b_shares, c_shares, d_shares = [], [], [], []
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
        elif typ == T_D_SHARE:
            d_shares.append(val)
        elif typ == T_CONFIRM:
            confirm = val
    assert sid is not None and confirm is not None
    assert len(a_shares) == 1 and len(b_shares) == 1
    assert len(c_shares) >= 1, "no C contribution"
    assert len(d_shares) >= 1, "no D contribution"
    # framing check: bound contributions carry a 16-byte binding tag, reduced
    # ones do not.  A and B are bound; C and D are reduced.
    assert len(a_shares[0]) == 48 and len(b_shares[0]) == 48
    assert all(len(v) == 32 for v in c_shares)
    assert all(len(v) == 32 for v in d_shares)
    return sid, a_shares[0], b_shares[0], c_shares, confirm


def _last_d_share():
    return [v for (t, v) in _records() if t == T_D_SHARE][-1]


def mix_Y(xa, xb, xc, xd):
    g = lambda b: int.from_bytes(b, "big")
    return (pow(g(xa), ALPHA, P) * pow(g(xb), BETA, P)
            * pow(g(xc), GAMMA, P) * pow(g(xd), DELTA, P)) % P


def kdf(sid, xa, xb, xc, xd):
    Y = mix_Y(xa, xb, xc, xd)
    return _hkdf(SALT, Y.to_bytes(32, "big"), INFO + sid, 32)


def inner_key(K):
    return _hkdf(INNER_SALT, K, INNER_INFO, 32)


def confirm_tag(K, sid, xa, xb, xc):
    return hmac.new(K, CONFIRM_LABEL + sid + xa + xb + xc,
                    hashlib.sha256).digest()[:16]


def decrypt_payload(K, blob=None):
    if blob is None:
        blob = (L.out_dir("H05") / "final_payload.enc").read_bytes()
    nonce, body = blob[:12], blob[12:]
    ct, tag = body[:-16], body[-16:]
    # stage 1: outer AES-256-GCM (raises ValueError on a wrong key)
    inner_blob = AES.new(K, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
    # stage 2: inner AES-256-CBC, 16-byte IV prefix, key = HKDF expansion of K
    iv, cbc = inner_blob[:16], inner_blob[16:]
    return unpad(AES.new(inner_key(K), AES.MODE_CBC, iv=iv).decrypt(cbc), 16)


def derive_with_share(share_bytes):
    """Derive a key using a caller-supplied C contribution (used to prove the
    wrong selection fails)."""
    sid, a_val, b_val, _c, _conf = load_transcript()
    return kdf(sid, a_val[:32], b_val[:32], share_bytes, _last_d_share())


def solve():
    sid, a_val, b_val, c_shares, confirm = load_transcript()
    XA, XB = a_val[:32], b_val[:32]
    XD = _last_d_share()

    # C's reduced contribution is taken verbatim and, being advertised twice,
    # the most recent advertisement wins.
    XC = c_shares[-1]

    K = kdf(sid, XA, XB, XC, XD)

    # confirm the key against the handshake's own key-confirmation tag
    assert confirm_tag(K, sid, XA, XB, XC) == confirm, \
        "derived key does not match the confirmation tag"

    pt = decrypt_payload(K).decode()
    flag = pt.split("flag=")[1].splitlines()[0].strip()
    assert flag == L.FLAGS["H05"], flag
    print("[H05] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
