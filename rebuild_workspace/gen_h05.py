#!/usr/bin/env python3
"""H05 - "Last Ride Out" (organizer generator).

A three-party contributed key-agreement handshake ("ESCAPE-3") over a fixed
256-bit prime field. Parties A, B and C each contribute a public share
X_i = g^{x_i} mod p and the session key is

    K = SHA-256( LABEL || session_id || X_A || X_B || X_C )

A and B bind their share with a 16-byte tag derived from long-term material;
C's share is accepted verbatim from the transcript and C is allowed to
re-advertise it. The captured transcript contains TWO 0x0012 records: C's
original share and a second, injected share. Per the protocol the most recent
C share is used, so the effective session key is the one built from the
INJECTED share. The captured `final_payload.enc` was sealed under exactly that
key, so anyone who recognises that C's word is taken on trust can rebuild the
key from the (public) transcript and open the payload.

Participant files written to L.out_dir("H05"):
    intercept.bin        raw TLV transcript (the captured handshake)
    final_payload.enc    nonce(12) || AES-256-GCM(ciphertext || tag)
    ESCAPE_PROTOCOL.md   protocol description (flaw framed as a feature)
    FORMAT_SPEC.txt      TLV framing only, no type semantics

Private organizer tooling; the flag never appears in any participant file.
"""
import hashlib, hmac, sys
from Crypto.Cipher import AES

sys.path.insert(0, r"d:\ctf\FLAG_THEFT_AUTO_FINAL\rebuild_workspace")
import lib_fta as L

# --- fixed 256-bit prime field (secp256k1 field prime) ----------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
GEN = 5
FG = "0x{:064x}".format(P)

# --- protocol constants -----------------------------------------------------
LABEL = b"ESCAPE-3/session-key/v1"                  # KDF domain tag (public)
BIND = b"escape-3/long-term-binding-material-2026"  # A/B binding secret (private)

T_VERSION, T_SID, T_SUITE = 0x0001, 0x0002, 0x0003
T_A_SHARE, T_B_SHARE, T_C_SHARE = 0x0010, 0x0011, 0x0012
T_CONFIRM, T_TRAILER = 0x0020, 0x0030


def _exp(seed: bytes) -> int:
    return int.from_bytes(hashlib.sha256(seed).digest(), "big") % (P - 1) + 1


def share(x: int) -> bytes:
    return pow(GEN, x, P).to_bytes(32, "big")


def bind_tag(who: bytes, X: bytes, sid: bytes) -> bytes:
    return hmac.new(BIND, who + X + sid, hashlib.sha256).digest()[:16]


def kdf(sid: bytes, xa: bytes, xb: bytes, xc: bytes) -> bytes:
    return hashlib.sha256(LABEL + sid + xa + xb + xc).digest()


def confirm_tag(K: bytes, sid: bytes, xa: bytes, xb: bytes, xc: bytes) -> bytes:
    return hmac.new(K, b"ESCAPE-3/confirm/v1" + sid + xa + xb + xc,
                    hashlib.sha256).digest()[:16]


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

Type codes seen on this wire (their meaning is defined elsewhere):
    0x0001  0x0002  0x0003  0x0010  0x0011  0x0012  0x0020  0x0030
"""

ESCAPE_PROTOCOL = """\
ESCAPE-3 - Three-Way Contributed Key Agreement
==============================================

Motive
------
Three parties who do not share a pairwise secret still want to mint one agreed
session key for the duration of a single ride. ESCAPE-3 lets each party toss a
public contribution into a common transcript; the contributions are folded into
one key that every participant can recompute from the transcript alone.

Field and encoding
------------------
  p = {P}
  g = {G}
  Field elements are serialised as 32-byte big-endian integers.

Handshake
---------
  * Each party i picks a private exponent x_i and advertises X_i = g^x_i mod p.
  * A and B append a 16-byte binding tag to their advertised share; the tag is
    derived from long-term party material and lets the receiver confirm the
    share belongs to the expected party.
  * C runs the reduced profile and advertises the bare share.
  * The parties then publish a key-confirmation tag so that each end can check
    it arrived at the same key before sending traffic.

Records (type code -> value content)
------------------------------------
  0x0001   version string, ASCII
  0x0002   session identifier, 8 bytes
  0x0003   cipher suite, ASCII
  0x0010   A's share: X_A (32 B) || binding tag (16 B)
  0x0011   B's share: X_B (32 B) || binding tag (16 B)
  0x0012   C's share: X_C (32 B)
  0x0020   key-confirmation tag, 16 bytes
  0x0030   trailer / status text

Key derivation
--------------
  K = SHA-256( LABEL || session_id || X_A || X_B || X_C )

  LABEL is the ASCII domain tag of this handshake, "ESCAPE-3/session-key/v1".
  session_id is the 8-byte value from record 0x0002. X_A, X_B and X_C are the
  advertised 32-byte shares in that order. The 32-byte digest is used directly
  as an AES-256 key.

Re-advertisement
----------------
C may advertise its share more than once inside a single handshake, for example
to rotate entropy part-way through. When more than one C share is present, the
most recently advertised one is the one that participates in the key.

Session traffic
---------------
  AES-256-GCM under K. The 12-byte nonce travels immediately ahead of the
  sealed body (ciphertext followed by the 16-byte authentication tag).
""".format(P=FG, G=GEN)


def main():
    out = L.out_dir("H05")

    sid = hashlib.sha256(b"last-ride-out/session/1").digest()[:8]
    nonce = hashlib.sha256(b"final_payload/nonce").digest()[:12]

    a = _exp(b"ESCAPE-3/party/A/2026")
    b = _exp(b"ESCAPE-3/party/B/2026")
    c = _exp(b"ESCAPE-3/party/C/2026")
    c_inj = _exp(b"ESCAPE-3/party/C/rotated/2026")     # attacker-injected exponent

    XA, XB = share(a), share(b)
    XC = share(c)               # C's original, honest contribution
    XC_INJ = share(c_inj)       # the injected (forged) contribution

    tag_a = bind_tag(b"A", XA, sid)
    tag_b = bind_tag(b"B", XB, sid)

    # real session key = built from the LAST (injected) C share
    K = kdf(sid, XA, XB, XC_INJ)
    conf = confirm_tag(K, sid, XA, XB, XC_INJ)

    transcript = b"".join([
        L.tlv(T_VERSION, b"ESCAPE-3"),
        L.tlv(T_SID, sid),
        L.tlv(T_SUITE, b"AES-256-GCM"),
        L.tlv(T_A_SHARE, XA + tag_a),
        L.tlv(T_B_SHARE, XB + tag_b),
        L.tlv(T_C_SHARE, XC),          # C's original share
        L.tlv(T_C_SHARE, XC_INJ),      # second, injected C share (wins)
        L.tlv(T_CONFIRM, conf),
        L.tlv(T_TRAILER, b"handshake complete"),
    ])
    (out / "intercept.bin").write_bytes(transcript)

    # seal the payload under the injected-share key
    payload = (b"ESCAPE-3 sealed payload\n"
               b"route=last-ride-out\n"
               b"session=" + sid.hex().encode() + b"\n"
               b"flag=" + L.FLAGS["H05"].encode() + b"\n")
    gcm = AES.new(K, AES.MODE_GCM, nonce=nonce)
    ct, tag = gcm.encrypt_and_digest(payload)
    (out / "final_payload.enc").write_bytes(nonce + ct + tag)

    # participant documentation
    (out / "ESCAPE_PROTOCOL.md").write_text(ESCAPE_PROTOCOL, encoding="utf-8")
    (out / "FORMAT_SPEC.txt").write_text(FORMAT_SPEC, encoding="utf-8")

    # --- self-consistency checks -------------------------------------------
    tlvs = L.read_tlvs(transcript)
    c_seen = [v for (t, v) in tlvs if t == T_C_SHARE]
    assert len(c_seen) == 2 and c_seen[-1] == XC_INJ, "C records wrong"
    assert XC != XC_INJ

    # the injected key opens the payload ...
    g2 = AES.new(K, AES.MODE_GCM, nonce=nonce)
    pt = g2.decrypt_and_verify(ct, tag)
    assert L.FLAGS["H05"].encode() in pt, "flag not embedded"
    # ... while the honest-share key does not
    K_orig = kdf(sid, XA, XB, XC)
    try:
        AES.new(K_orig, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)
        raise SystemExit("honest-share key unexpectedly opened the payload")
    except ValueError:
        pass

    print("[H05] intercept.bin = {} bytes, {} records".format(len(transcript), len(tlvs)))
    print("[H05] final_payload.enc = {} bytes (nonce||ct||tag)".format(12 + len(ct) + len(tag)))
    print("[H05] injected-share key opens payload; honest-share key rejected")


if __name__ == "__main__":
    main()
