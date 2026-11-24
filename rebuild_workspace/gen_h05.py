#!/usr/bin/env python3
"""H05 - "Last Ride Out" (organizer generator).

ESCAPE-3 multi-party profile.  Four contributing seats (A, B, C, D) each toss a
public field element X_i = g^{x_i} mod p into a shared transcript.  Two seats
(A, B) run the *bound* profile and append a 16-byte binding tag to their share;
two seats (C, D) run the *reduced* profile and advertise the bare 32-byte
element - their word is accepted on faith and may be re-advertised later in the
same handshake.

The session key is *not* a flat hash of the shares.  The agreement value is the
weighted product

    Y = X_A^a * X_B^b * X_C^c * X_D^d   (mod p)

with public exponents (a,b,c,d)=(5,11,13,17), and the AES-256 key is the HKDF
(extract-then-expand) of Y under a fixed salt with the session id as info.

Because C is unauthenticated it can re-advertise; the most recent C share wins.
An attacker who wants to steer the key chooses that re-advertised value so that
the weighted product lands on a target element Y*, i.e. it solves

    X_C^c = Y* * (X_A^a * X_B^b * X_D^d)^(-1)   (mod p)
    X_C   = rhs^(c^(-1) mod (p-1))              (mod p)

a single modular-exponent algebra step.  The captured transcript therefore
carries an injected C share that was chosen this way, and the sealed payload was
keyed off exactly that Y*.

Layering on top of the protocol break, the shipped `final_payload.enc` is a
two-stage ciphertext: the outer AES-256-GCM body wraps an INNER AES-256-CBC
blob (IV prepended), itself keyed by an HKDF expansion of the outer key.  Decoys
(non-protocol record types, a decoy legacy share, and decoy key-confirmation
tags that match *wrong* keys) are interleaved so that a wrong share selection
yields a plausible-but-broken decryption path.

Participant files written to L.out_dir("H05"):
    intercept.bin        raw TLV transcript (the captured handshake)
    final_payload.enc    nonce(12) || AES-256-GCM( inner_cbc_blob || tag )
    ESCAPE_PROTOCOL.md   protocol description (intent; the reduced profile is
                         never framed as "unverified")
    FORMAT_SPEC.txt      TLV framing only, no type semantics

Private organizer tooling; the flag never appears in any participant file.
"""
import hashlib, hmac, sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

sys.path.insert(0, r"d:\ctf\FLAG_THEFT_AUTO_FINAL\rebuild_workspace")
import lib_fta as L

# --- fixed 256-bit prime field (secp256k1 field prime) ----------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
GEN = 5
FG = "0x{:064x}".format(P)

# --- protocol constants -----------------------------------------------------
SALT = b"ESCAPE-3/hkdf/salt/v2"                     # HKDF salt (public)
INFO = b"ESCAPE-3/session-key/v2"                   # HKDF info prefix (public)
CONFIRM_LABEL = b"ESCAPE-3/confirm/v2"              # confirm-tag domain (public)
INNER_SALT = b"ESCAPE-3/inner-cbc/v2"               # inner-KDF salt (public)
INNER_INFO = b"inner-vault"                         # inner-KDF info (public)
BIND = b"escape-3/long-term-binding-material-2026"  # A/B binding secret (private)

# public mixing exponents of the weighted-product agreement value
ALPHA, BETA, GAMMA, DELTA = 5, 11, 13, 17

# record types (protocol)
T_VERSION, T_SID, T_SUITE = 0x0001, 0x0002, 0x0003
T_A_SHARE, T_B_SHARE, T_C_SHARE, T_D_SHARE = 0x0010, 0x0011, 0x0012, 0x0013
T_CONFIRM, T_TRAILER = 0x0020, 0x0030
# decoy record types (not part of the protocol)
T_DEC_ROUTE = 0x0005
T_DEC_RESUME = 0x0007
T_DEC_NONCE = 0x0008
T_DEC_LEGACY = 0x0014
T_CONFIRM_DECOY_A = 0x0021
T_CONFIRM_DECOY_B = 0x0022


def _exp(seed: bytes) -> int:
    return int.from_bytes(hashlib.sha256(seed).digest(), "big") % (P - 1) + 1


def share(x: int) -> bytes:
    return pow(GEN, x, P).to_bytes(32, "big")


def bind_tag(who: bytes, X: bytes, sid: bytes) -> bytes:
    return hmac.new(BIND, who + X + sid, hashlib.sha256).digest()[:16]


def _hkdf(salt: bytes, ikm: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, t, ctr = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([ctr]), hashlib.sha256).digest()
        okm += t
        ctr += 1
    return okm[:length]


def mix_Y(xa: bytes, xb: bytes, xc: bytes, xd: bytes) -> int:
    g = lambda b: int.from_bytes(b, "big")
    return (pow(g(xa), ALPHA, P) * pow(g(xb), BETA, P)
            * pow(g(xc), GAMMA, P) * pow(g(xd), DELTA, P)) % P


def kdf(sid: bytes, xa: bytes, xb: bytes, xc: bytes, xd: bytes) -> bytes:
    Y = mix_Y(xa, xb, xc, xd)
    return _hkdf(SALT, Y.to_bytes(32, "big"), INFO + sid, 32)


def inner_key(K: bytes) -> bytes:
    return _hkdf(INNER_SALT, K, INNER_INFO, 32)


def confirm_tag(K: bytes, sid: bytes, xa: bytes, xb: bytes, xc: bytes) -> bytes:
    return hmac.new(K, CONFIRM_LABEL + sid + xa + xb + xc,
                    hashlib.sha256).digest()[:16]


def steer_C(Y_target: int, xa: bytes, xb: bytes, xd: bytes) -> bytes:
    """Solve for the injected C share that steers the weighted product to Y*."""
    g = lambda b: int.from_bytes(b, "big")
    rest = (pow(g(xa), ALPHA, P) * pow(g(xb), BETA, P) * pow(g(xd), DELTA, P)) % P
    rhs = (Y_target * pow(rest, -1, P)) % P
    XC = pow(rhs, pow(GAMMA, -1, P - 1), P)
    return XC.to_bytes(32, "big")


FORMAT_SPEC = """\
ESCAPE-3 wire framing - FORMAT SPECIFICATION
============================================

The handshake transcript is a flat byte stream made of concatenated records.
This document specifies ONLY the framing. It deliberately does not define the
meaning of any type code; that belongs to the protocol description.

Record layout - all integers are BIG-ENDIAN:

    +--------+--------+---------------------------+
    | type   | length | value                     |
    | 2 B    | 4 B    | `length` bytes            |
    +--------+--------+---------------------------+

    type    : uint16, big-endian
    length  : uint32, big-endian, byte count of value
    value   : opaque byte string, `length` bytes long

Records are packed back-to-back with no padding and no separators. A reader
consumes one record, advances by 6 + length bytes, and repeats until the
buffer is exhausted.

Lengths observed on this wire (bytes):
    4   8   11   12   16   18   27   32   40   48

Type codes seen on this wire (their meaning is defined elsewhere):
    0x0001  0x0002  0x0003  0x0005  0x0007  0x0008  0x0010  0x0011
    0x0012  0x0013  0x0014  0x0020  0x0021  0x0022  0x0030
"""

ESCAPE_PROTOCOL = """\
ESCAPE-3 - Multi-Party Contributed Key Agreement
================================================

Motive
------
Several parties who share no pairwise secret still want to mint one agreed
session key for the duration of a single ride. ESCAPE-3 lets every party toss a
public contribution into a common transcript; the contributions are folded into
one key that any participant can recompute from the transcript alone.

Field and encoding
------------------
  p = {P}
  g = {G}
  Field elements are serialised as 32-byte big-endian integers.

Handshake
---------
  * Each participating party i picks a private exponent x_i and advertises
    X_i = g^x_i mod p.
  * A party may advertise under either of two profiles:
      - the BOUND profile, which appends a 16-byte binding tag to the
        advertised element (the tag is derived from long-term party material
        and lets a receiver confirm the element belongs to the expected party);
      - the REDUCED profile, which advertises the bare field element.
    Both profiles are valid on the wire; a receiver decides from the record
    framing which profile a given contribution used.
  * Parties may re-advertise a contribution more than once inside a single
    handshake, for example to rotate entropy part-way through. When a party
    advertises its contribution more than once, the most recently advertised
    element is the one that participates in the key.
  * The handshake closes with a key-confirmation tag so each end can check it
    arrived at the same key before sending traffic.

Records (type code -> value content)
------------------------------------
  0x0001   version string, ASCII
  0x0002   session identifier, 8 bytes
  0x0003   cipher suite, ASCII
  0x0010   A's contribution (bound):   X_A (32 B) || binding tag (16 B)
  0x0011   B's contribution (bound):   X_B (32 B) || binding tag (16 B)
  0x0012   C's contribution:           X_C (32 B)
  0x0013   D's contribution:           X_D (32 B)
  0x0020   key-confirmation tag, 16 bytes
  0x0030   trailer / status text

Key derivation
--------------
The agreement value is a weighted product of the four advertised elements:

    Y = X_A^a * X_B^b * X_C^c * X_D^d   (mod p)

with public weighting exponents (a, b, c, d) = (5, 11, 13, 17). The 32-byte
session key is then the HKDF of Y:

    K = HKDF-Extract(salt = "ESCAPE-3/hkdf/salt/v2", IKM = Y)
    K = HKDF-Expand(PRK, info = "ESCAPE-3/session-key/v2" || session_id, 32)

The 32-byte result is used directly as an AES-256 key. The exponents are chosen
so that the weighted product is a group homomorphism in every contribution:
holding the other three factors fixed, varying X_i traces the whole field as
X_i is raised to the i-th power.

Weighting and steering
----------------------
Because the weighted product is multiplicative, a party that controls a single
contribution can steer the agreement value to any element of the field. Fix the
other three factors as R = X_A^a * X_B^b * X_D^d. To force the agreement onto a
chosen target Y*, the controlled element X_i must satisfy

    X_i^w = Y* * R^(-1)   (mod p)
    X_i   = (Y* * R^(-1))^(w^(-1) mod (p-1))   (mod p)

i.e. one modular inverse and one modular exponentiation. Whoever owns a
contribution that the protocol accepts without independent proof can therefore
select the resulting session key outright.

Re-advertisement
----------------
A contribution may appear more than once. The most recently advertised element
of a given party is the one that participates in the key; earlier
advertisements are superseded and remain in the transcript only as history.

Session traffic
---------------
Traffic is doubly wrapped. The outer layer is AES-256-GCM under the session key
K: a 12-byte nonce travels immediately ahead of the sealed body (ciphertext
followed by the 16-byte authentication tag). The GCM plaintext is itself an
inner AES-256-CBC blob - a 16-byte IV followed by CBC ciphertext - keyed by an
HKDF expansion of K:

    K_inner = HKDF-Extract(salt = "ESCAPE-3/inner-cbc/v2", IKM = K)
    K_inner = HKDF-Expand(PRK, info = "inner-vault", 32)

Opening the payload therefore requires two decryption stages in sequence.
""".format(P=FG, G=GEN)


def main():
    out = L.out_dir("H05")

    sid = hashlib.sha256(b"last-ride-out/session/1").digest()[:8]
    nonce = hashlib.sha256(b"final_payload/nonce").digest()[:12]
    iv = hashlib.sha256(b"ESCAPE-3/inner-iv/v2").digest()[:16]

    # the weighting exponents must be invertible modulo the group order
    assert pow(GAMMA, -1, P - 1) and pow(DELTA, -1, P - 1), "exponent not invertible"

    a = _exp(b"ESCAPE-3/party/A/2026")
    b = _exp(b"ESCAPE-3/party/B/2026")
    c = _exp(b"ESCAPE-3/party/C/2026")
    d = _exp(b"ESCAPE-3/party/D/2026")
    d_inj = _exp(b"ESCAPE-3/party/D/rotated/2026")

    XA, XB = share(a), share(b)
    XC = share(c)               # C's original, honest contribution
    XD = share(d)               # D's original, honest contribution
    XD_INJ = share(d_inj)       # D's re-advertised contribution

    # the attacker fixes a target agreement value and SOLVES for the C share
    # that steers the weighted product onto it.
    Y_target = _exp(b"ESCAPE-3/agreement/target/2026") % P
    XC_INJ = steer_C(Y_target, XA, XB, XD_INJ)
    assert XC_INJ != XC

    tag_a = bind_tag(b"A", XA, sid)
    tag_b = bind_tag(b"B", XB, sid)

    # real session key = built from the effective (last) C and D contributions
    K = kdf(sid, XA, XB, XC_INJ, XD_INJ)
    conf = confirm_tag(K, sid, XA, XB, XC_INJ)
    # decoy key-confirmations that match WRONG selections
    conf_dec_a = confirm_tag(kdf(sid, XA, XB, XC, XD), sid, XA, XB, XC)
    conf_dec_b = confirm_tag(kdf(sid, XA, XB, XC_INJ, XD), sid, XA, XB, XC_INJ)
    assert conf != conf_dec_a and conf != conf_dec_b

    transcript = b"".join([
        L.tlv(T_VERSION, b"ESCAPE-3"),
        L.tlv(T_SID, sid),
        L.tlv(T_SUITE, b"AES-256-GCM/CBC"),
        L.tlv(T_DEC_ROUTE, b"route=last-ride-out"),
        L.tlv(T_A_SHARE, XA + tag_a),
        L.tlv(T_DEC_LEGACY, share(_exp(b"ESCAPE-3/decoy/legacy/2026"))),
        L.tlv(T_B_SHARE, XB + tag_b),
        L.tlv(T_C_SHARE, XC),               # C's original contribution
        L.tlv(T_D_SHARE, XD),               # D's original contribution
        L.tlv(T_DEC_RESUME, b"resume=7f3a91c4d2e8b6a0"),
        L.tlv(T_C_SHARE, XC_INJ),           # re-advertised C (steered, wins)
        L.tlv(T_DEC_NONCE, b"hint-blocks=4"),
        L.tlv(T_D_SHARE, XD_INJ),           # re-advertised D (wins)
        L.tlv(T_CONFIRM_DECOY_A, conf_dec_a),
        L.tlv(T_CONFIRM, conf),             # real key-confirmation
        L.tlv(T_CONFIRM_DECOY_B, conf_dec_b),
        L.tlv(T_TRAILER, b"handshake complete"),
    ])
    (out / "intercept.bin").write_bytes(transcript)

    # --- two-stage sealed payload -----------------------------------------
    inner_pt = (b"ESCAPE-3 inner vault\n"
                b"route=last-ride-out\n"
                b"session=" + sid.hex().encode() + b"\n"
                b"flag=" + L.FLAGS["H05"].encode() + b"\n"
                b"exit=confirmed\n")
    inner_ct = AES.new(inner_key(K), AES.MODE_CBC, iv=iv).encrypt(pad(inner_pt, 16))
    inner_blob = iv + inner_ct
    gcm = AES.new(K, AES.MODE_GCM, nonce=nonce)
    ct, tag = gcm.encrypt_and_digest(inner_blob)
    (out / "final_payload.enc").write_bytes(nonce + ct + tag)

    # participant documentation
    (out / "ESCAPE_PROTOCOL.md").write_text(ESCAPE_PROTOCOL, encoding="utf-8")
    (out / "FORMAT_SPEC.txt").write_text(FORMAT_SPEC, encoding="utf-8")

    # --- self-consistency checks -------------------------------------------
    tlvs = L.read_tlvs(transcript)
    c_seen = [v for (t, v) in tlvs if t == T_C_SHARE]
    d_seen = [v for (t, v) in tlvs if t == T_D_SHARE]
    assert len(c_seen) == 2 and c_seen[-1] == XC_INJ, "C records wrong"
    assert len(d_seen) == 2 and d_seen[-1] == XD_INJ, "D records wrong"
    assert XC != XC_INJ and XD != XD_INJ

    # the steered key opens the payload (two decryptions) ...
    got_inner = AES.new(K, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
    got_pt = unpad(AES.new(inner_key(K), AES.MODE_CBC, iv=got_inner[:16])
                   .decrypt(got_inner[16:]), 16)
    assert L.FLAGS["H05"].encode() in got_pt, "flag not embedded"
    # ... while the honest-selection keys do not
    for K_wrong in (kdf(sid, XA, XB, XC, XD),
                    kdf(sid, XA, XB, XC_INJ, XD),
                    kdf(sid, XA, XB, XC, XD_INJ)):
        try:
            AES.new(K_wrong, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
            raise SystemExit("a wrong selection unexpectedly opened the payload")
        except ValueError:
            pass

    # the flag plaintext never appears as raw bytes in a participant file
    flag_b = L.FLAGS["H05"].encode()
    for name in ("intercept.bin", "final_payload.enc",
                 "ESCAPE_PROTOCOL.md", "FORMAT_SPEC.txt"):
        assert flag_b not in (out / name).read_bytes(), f"flag leaked into {name}"

    print("[H05] intercept.bin = {} bytes, {} records".format(len(transcript), len(tlvs)))
    print("[H05] final_payload.enc = {} bytes (gcm: nonce||ct||tag over inner cbc)"
          .format(12 + len(ct) + len(tag)))
    print("[H05] steered-share key opens nested payload; wrong selections rejected")


if __name__ == "__main__":
    main()
