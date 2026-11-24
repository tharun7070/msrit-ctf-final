#!/usr/bin/env python3
"""E01 — Lester's Pager Panic. Generator (private, hardened).

Stacked layers:
  1. DUAL MODULAR FILTER. Genuine courier rows satisfy BOTH
         (col_A * col_B) % col_C == 7
     AND (col_A + col_B) % col_C == (col_D % col_C)
     Decoys satisfy exactly one of the two, so a single-filter attack pulls in
     garbage and corrupts the reconstructed message.
  2. PER-ROW KEYED AFFINE PERMUTATION over the 41-symbol alphabet. Each chunk
     is base-41 encoded and then every character is remapped by
         idx -> (k*idx + m) % 41,   k = 1 + (col_A % 40),  m = col_D % 41.
     A naive base-41 decode of a payload therefore yields garbage.
  3. TRIPLE-KEY ORDERING + PAD STRIP. Genuine rows are ordered by
         (col_C % 5 asc, col_D % 2 asc, -col_E desc, packet_id asc)
     and the concatenated plaintext is prefixed with a fixed 2-byte marker
     that must be stripped before the flag is read.
  4. DECOY PAYLOAD. A non-genuine row whose payload, decoded naively as
     base-41, yields a plausible but WRONG FTA{...} string.

Deterministic: a fixed RNG seed makes dispatch.csv byte-identical across runs.
"""
import csv, random, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

FLAG = L.FLAGS["E01"]
CHUNK = 7                       # plaintext chunk size (bytes)
MARKER = b"\x1b\x13"            # fixed 2-byte tag prefixed to the plaintext
TOTAL_ROWS = 200
RNG_SEED = 0x1337E01
WRONG_FLAG = "FTA{41_c1ph3r_b4s3_cust0m_m0d_p4g3r_d3c0y_2026}"


def _permute(text, k, m):
    a = L.BASE41_ALPHABET
    return "".join(a[(k * a.index(ch) + m) % L.BASE41] for ch in text)


def _encode_chunk(chunk, A, D):
    """base-41 encode, then apply the per-row affine alphabet permutation."""
    k = 1 + (A % 40)
    m = D % 41
    return _permute(L.base41_encode(chunk), k, m)


def _find_ab(C, r, rnd):
    """Return (A, B) with (A*B)%C == 7 and (A+B)%C == r, both within [10, 500]."""
    residues = list(range(C))
    rnd.shuffle(residues)
    for A in residues:
        B0 = (r - A) % C
        if (A * B0) % C != 7:
            continue
        A2 = A
        while A2 < 10:
            A2 += C
        B2 = B0
        while B2 < 10:
            B2 += C
        if A2 <= 500 and B2 <= 500:
            return A2, B2
    return None


def _genuine(i, rnd):
    """Build a genuine row for chunk i: both congruences hold and its sort slot
    (pk, sk, E) = (i//2, i%2, 900-40i) places it exactly at position i."""
    pk, sk = i // 2, i % 2
    E = 900 - 40 * i
    cand = [c for c in range(30, 201) if c % 5 == pk]
    for _ in range(4000):
        C = rnd.choice(cand)
        D = rnd.randrange(200, 1000)
        if D % 2 != sk:
            D += 1
        sol = _find_ab(C, D % C, rnd)
        if sol is None:
            continue
        A, B = sol
        return A, B, C, D, E
    raise RuntimeError("genuine row search failed")


def _decoy_x(rnd):
    """Satisfies condition 1 only: (A*B)%C == 7, but (A+B)%C != D%C."""
    while True:
        A, B, C = rnd.randint(10, 500), rnd.randint(10, 500), rnd.randint(30, 200)
        if (A * B) % C != 7:
            continue
        D = rnd.randint(200, 999)
        if (A + B) % C == D % C:
            continue
        return A, B, C, D, rnd.randint(100, 900)


def _decoy_y(rnd):
    """Satisfies condition 2 only: (A+B)%C == D%C, but (A*B)%C != 7."""
    while True:
        A, B, C = rnd.randint(10, 500), rnd.randint(10, 500), rnd.randint(30, 200)
        if (A * B) % C == 7:
            continue
        D = (A + B) % C
        while D < 200:
            D += C
        if D > 999:
            continue
        return A, B, C, D, rnd.randint(100, 900)


def _rand_payload(rnd):
    return "".join(rnd.choice(L.BASE41_ALPHABET) for _ in range(rnd.randint(5, 9)))


def _pk(rnd):
    return f"PKT-{rnd.randint(10000, 99999)}"


def main():
    plaintext = MARKER + FLAG.encode()
    chunks = [plaintext[i:i + CHUNK] for i in range(0, len(plaintext), CHUNK)]

    rnd = random.Random(RNG_SEED)
    rows = []

    # Layer 1 + 2: genuine courier rows (both congruences, affine-permuted payload).
    for i, chunk in enumerate(chunks):
        A, B, C, D, E = _genuine(i, rnd)
        rows.append([_pk(rnd), A, B, C, D, E, _encode_chunk(chunk, A, D)])
    n_genuine = len(rows)

    # Layer 4: plausible-but-wrong flag payload, sitting on a condition-1-only row.
    A, B, C, D, E = _decoy_x(rnd)
    rows.append([_pk(rnd), A, B, C, D, E, L.base41_encode(WRONG_FLAG.encode())])
    n_x = 1
    for _ in range(3):                                   # more condition-1-only decoys
        A, B, C, D, E = _decoy_x(rnd)
        rows.append([_pk(rnd), A, B, C, D, E, _rand_payload(rnd)])
        n_x += 1
    n_y = 0
    for _ in range(3):                                   # condition-2-only decoys
        A, B, C, D, E = _decoy_y(rnd)
        rows.append([_pk(rnd), A, B, C, D, E, _rand_payload(rnd)])
        n_y += 1

    # Filler: satisfy neither congruence (explicitly fail condition 1).
    while len(rows) < TOTAL_ROWS:
        A, B, C = rnd.randint(10, 500), rnd.randint(10, 500), rnd.randint(30, 200)
        if (A * B) % C == 7:
            continue
        rows.append([_pk(rnd), A, B, C,
                     rnd.randint(10, 999), rnd.randint(100, 999), _rand_payload(rnd)])

    rnd.shuffle(rows)

    p = L.out_dir("E01") / "dispatch.csv"
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["packet_id", "col_A", "col_B", "col_C", "col_D", "col_E", "payload"])
        w.writerows(rows)
    filler = len(rows) - n_genuine - n_x - n_y
    print(f"[E01] wrote {len(rows)} rows -> {p}")
    print(f"[E01] genuine={n_genuine} decoys={n_x + n_y} "
          f"(cond1-only={n_x}, cond2-only={n_y}) filler={filler}")
    print(f"[E01] flag = {FLAG}")


if __name__ == "__main__":
    main()
