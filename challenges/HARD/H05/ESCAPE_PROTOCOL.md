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
  p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
  g = 5
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
