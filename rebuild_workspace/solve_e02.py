#!/usr/bin/env python3
"""E02 -- Vinewood Shift Change. Reference solver (organizer proof).

Faithful inverse of gen_e02.py:

  1. DUAL CHECKSUM GATE -- keep only the row whose SHA1(timestamp) ends in "a3"
     AND whose SHA256(route) starts with the nibble "4"; assert it is unique and
     that >= 3 near-miss rows satisfy exactly one gate.
  2. TWO-STAGE CIPHER -- recover the columnar-transposition width and the affine
     (a,b) jointly from frequency_sample.bin (the width is the integer key); a
     single affine inverse of the payload must NOT yield the flag.
  3. KEY DERIVATION -- the sample is affine(transpose(english)); only after
     inverting the transposition does it read as English and pin (a,b)=(7,11).
     A naive "most frequent -> e, next -> t" pass on the raw sample is shown to
     return a wrong pair.
  4. DECOYS -- assert the Caesar-5 row decrypts to "FTA{wrong_route}" and that a
     single-stage affine row decrypts to a plausible-but-wrong FTA{...}.
"""
import hashlib, sys, collections
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

EXPECT_W, EXPECT_A, EXPECT_B = 9, 7, 11
COP = (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)

# Standard English letter frequencies (percent) for the chi-squared tiebreak.
ENGLISH_PCT = {
    "e": 12.70, "t": 9.06, "a": 8.17, "o": 7.51, "i": 6.97, "n": 6.75, "s": 6.33,
    "h": 6.09, "r": 5.99, "d": 4.25, "l": 4.03, "c": 2.78, "u": 2.76, "m": 2.41,
    "w": 2.36, "f": 2.23, "g": 2.02, "y": 1.97, "p": 1.93, "b": 1.49, "v": 0.98,
    "k": 0.77, "j": 0.15, "x": 0.15, "q": 0.10, "z": 0.07,
}
COMMON = set(
    "the a an and or of to in on at by for with is are was were be been being it "
    "its as from then when before after so which who what another through along "
    "toward towards near any no not nothing up out run runs ran night shift north "
    "northern south southbound convoy signal that this these those there their "
    "have has had he she they them his her we you your our all would could should "
    "them make made take took give gave one two three new old good bad long short "
    "into over under about after before more most some such than only also back "
    "again away down off still just even here will can may must".split()
)


def columnar_dec(text: str, w: int) -> str:
    n = len(text)
    assert n % w == 0
    r = n // w
    return "".join(text[j * r + i] for i in range(r) for j in range(w))


def gate_time(ts: str) -> bool:
    return hashlib.sha1(ts.encode()).hexdigest().endswith("a3")


def gate_route(route: str) -> bool:
    return hashlib.sha256(route.encode()).hexdigest().startswith("4")


def english_score(text: str) -> float:
    words = [w.strip(".,;:!?\"'()[]") for w in text.lower().split()]
    wscore = sum(1 for w in words if w in COMMON)
    letters = [c for c in text.lower() if "a" <= c <= "z"]
    n = len(letters) or 1
    cnt = collections.Counter(letters)
    chi2 = 0.0
    for ch, pct in ENGLISH_PCT.items():
        exp = pct * n / 100.0
        chi2 += (cnt.get(ch, 0) - exp) ** 2 / exp
    return wscore * 1000.0 - chi2


def recover_sample_params(sample: str):
    best = None
    for w in range(1, 25):
        if len(sample) % w:
            continue
        for a in COP:
            for b in range(26):
                dec = columnar_dec(L.affine_dec(sample, a, b), w)
                s = english_score(dec)
                if best is None or s > best[0]:
                    best = (s, w, a, b, dec)
    _, w, a, b, _ = best
    return w, a, b


def solve():
    out = L.out_dir("E02")
    rows = [[c.strip() for c in ln.split("|")]
            for ln in (out / "taxi_ledger.txt").read_text(encoding="utf-8").splitlines()
            if ln.strip()]
    assert all(len(r) == 5 for r in rows), "malformed ledger row"

    # 1) dual checksum gate -------------------------------------------------
    genuine = [r for r in rows if gate_time(r[0]) and gate_route(r[1])]
    assert len(genuine) == 1, f"expected exactly one dual-gate row, got {len(genuine)}"
    near_miss = sum(1 for r in rows if gate_time(r[0]) ^ gate_route(r[1]))
    assert near_miss >= 3, f"expected >=3 single-gate near-misses, got {near_miss}"
    ts, route, _cab, _status, payload = genuine[0]

    # 2+3) recover transposition width + affine params from the sample ------
    sample = (out / "frequency_sample.bin").read_bytes().decode()
    w, a, b = recover_sample_params(sample)
    assert (w, a, b) == (EXPECT_W, EXPECT_A, EXPECT_B), f"sample gave {(w, a, b)}"

    # naive single-letter attack on the RAW sample (must be wrong).
    raw = collections.Counter(c for c in sample.lower() if "a" <= c <= "z")
    c1 = ord(raw.most_common(1)[0][0]) - 97
    c2 = ord(raw.most_common(2)[1][0]) - 97
    a_naive = 7 * (c2 - c1) % 26
    b_naive = (c1 - 4 * a_naive) % 26
    assert (a_naive, b_naive) != (EXPECT_A, EXPECT_B)

    # a single affine inverse of the payload must NOT already be the flag.
    assert L.affine_dec(payload, a, b) != L.FLAGS["E02"]

    # 4) decoys -------------------------------------------------------------
    assert any(L.caesar_enc(r[4], 21) == "FTA{wrong_route}" for r in rows), "missing Caesar decoy"
    wrong_affine = [L.affine_dec(r[4], a, b) for r in rows]
    assert any(s.startswith("FTA{") and s != L.FLAGS["E02"] for s in wrong_affine), \
        "missing plausible affine decoy"

    # two-stage inverse of the genuine payload ------------------------------
    flag = columnar_dec(L.affine_dec(payload, a, b), w)
    assert flag == L.FLAGS["E02"], flag

    print(f"[E02] genuine row : {ts} | {route}")
    print(f"[E02] sample -> width={w} affine=({a},{b}); naive sample guess=({a_naive},{b_naive}) [wrong]")
    print(f"[E02] dual-gate=1 near-misses={near_miss}; decoys: Caesar-5 + single-stage affine")
    print("[E02] PASS ->", flag)
    return flag


if __name__ == "__main__":
    solve()
