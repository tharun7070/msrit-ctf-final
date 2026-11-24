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
  p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
  g = 5
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
