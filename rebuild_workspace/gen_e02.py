#!/usr/bin/env python3
"""E02 -- Vinewood Shift Change. Generator (private).

Stacked layers (all deterministic, fixed seed):

  L1 DUAL CHECKSUM GATE
     The genuine ledger row is the ONLY row whose timestamp satisfies BOTH
     gates at once:
        * SHA1(timestamp).hexdigest() ends with "a3"
        * SHA256(route).hexdigest() starts with the nibble "4"
     Four near-miss rows are planted that satisfy exactly one of the two gates.

  L2 TWO-STAGE CIPHER
     The genuine payload is affine(a=7,b=11) applied ON TOP OF a columnar
     transposition of width 9. A single affine inverse therefore yields
     transposed garbage. The transposition width is the short integer key; it
     is recoverable from the sample block (its length, 405 = 9 * 45, shares the
     width factor with the payload) and by trying candidate widths.

  L3 KEY DERIVATION
     frequency_sample.bin is affine(transpose(english), 7, 11): the sample is
     transposed the SAME way. Its single-letter histogram is affine(english) by
     construction, so a naive "most frequent -> e, next -> t" pass over the raw
     block returns a plausible but WRONG (a,b). Only after inverting the
     transposition does the block read as real English and pin (7,11).

  L4 DECOYS
     * A Caesar-5 row decrypting to "FTA{wrong_route}".
     * A row whose payload affine-decrypts (single stage) to a plausible but
       WRONG flag "FTA{...c0nv0y_00}" (the real one ends "99}").

Nothing in the artifacts documents any of this.
"""
import hashlib, random, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

FLAG = L.FLAGS["E02"]

A, B = 7, 11          # affine parameters
TW = 9                # columnar-transposition width (short integer key)
NIBBLE = "4"          # SHA256(route) must start with this nibble  (GATE 2)
GENUINE_ROUTE = "ROUTE-99-ALPHA"          # sha256 starts with '4'

WRONG_CAESAR = "FTA{wrong_route}"          # Caesar-5 decoy
WRONG_AFFINE = "FTA{4ff1n3_v1n3w00d_sh1ft_c0nv0y_00}"  # single-stage affine decoy

# 400+ chars of plain English, length forced to an exact multiple of TW
# (441 = 9 * 49). The genuine payload is 36 = 9 * 4, so sample length and
# payload length share the width factor 9 and nothing else trivial. The passage
# is deliberately letter-skewed (its most common letter is not 'e'), so a naive
# "most common -> e" pass yields a valid-but-wrong (a,b); only inverting the
# transposition reveals readable English and pins (7,11).
PASSAGE = (
    "The northern night shift runs a tight convoy through the winding canyon. "
    "Nine henchmen handle the handoff near the neon sign, then vanish when the "
    "signal changes. Any newcomer needs a short handshake before the inner gate "
    "opens. Nothing in the ledger mentions which run is genuine, so the crew "
    "counts on the shift pattern and the changing lanes. Another runner brings a "
    "bundle and then turns north along the avenue toward the northern hangar."
)[:441]


# ---------------------------------------------------------------------------
# Layer 2: columnar transposition (width key)
# ---------------------------------------------------------------------------
def columnar_enc(text: str, w: int) -> str:
    n = len(text)
    assert n % w == 0
    r = n // w
    return "".join(text[i * w + j] for j in range(w) for i in range(r))


def columnar_dec(text: str, w: int) -> str:
    n = len(text)
    assert n % w == 0
    r = n // w
    return "".join(text[j * r + i] for i in range(r) for j in range(w))


# ---------------------------------------------------------------------------
# Gate predicates (Layer 1)
# ---------------------------------------------------------------------------
def gate_time(ts: str) -> bool:
    return hashlib.sha1(ts.encode()).hexdigest().endswith("a3")


def gate_route(route: str) -> bool:
    return hashlib.sha256(route.encode()).hexdigest().startswith(NIBBLE)


def main():
    # Sanity: our chosen constants really satisfy the gates.
    assert hashlib.sha256(GENUINE_ROUTE.encode()).hexdigest().startswith(NIBBLE)
    assert len(FLAG) % TW == 0 and len(PASSAGE) % TW == 0

    out = L.out_dir("E02")

    # ---- Layer 3: transposed-then-affine English sample ------------------
    sample_ct = L.affine_enc(columnar_enc(PASSAGE, TW), A, B)
    (out / "frequency_sample.bin").write_bytes(sample_ct.encode())
    # ---- Layer 2: transposed-then-affine flag payload --------------------
    flag_inner = columnar_enc(FLAG, TW)
    flag_payload = L.affine_enc(flag_inner, A, B)

    rnd = random.Random(0x1337E02)
    used_ts = set()

    def gen_ts(want_a3: bool) -> str:
        while True:
            t = (f"2026-11-20T{rnd.randint(0,23):02d}:{rnd.randint(0,59):02d}:"
                 f"{rnd.randint(0,59):02d}.{rnd.randint(100,999)}Z")
            if t in used_ts:
                continue
            if gate_time(t) == want_a3:
                used_ts.add(t)
                return t

    SUFFIXES = ["ALFA", "BRAVO", "DELTA", "ECHO", "KILO", "TANGO", "ZULU", "OMEGA", "SIGMA"]

    def gen_route(match_nibble: bool) -> str:
        while True:
            rt = f"ROUTE-{rnd.randint(10,89)}-{rnd.choice(SUFFIXES)}"
            if gate_route(rt) == match_nibble:
                return rt

    def noise_payload() -> str:
        return L.caesar_enc(
            f"TRANSIT_NOTE_{rnd.randint(1000,9999)}_SIGNAL_LOSS_{rnd.randint(100,999)}",
            rnd.choice([3, 5, 9, 17]))

    rows = []

    # Genuine row: satisfies BOTH gates (unique).
    rows.append(f"{gen_ts(True)} | {GENUINE_ROUTE} | CAB-104 | DISPATCHED | {flag_payload}")

    # Near-miss 1 (SHA1 only) -- Caesar-5 decoy.
    rows.append(f"{gen_ts(True)} | {gen_route(False)} | CAB-077 | TERMINATED | "
                f"{L.caesar_enc(WRONG_CAESAR, 5)}")

    # Near-miss 2 (SHA1 only) -- extra noise.
    rows.append(f"{gen_ts(True)} | {gen_route(False)} | CAB-{rnd.randint(101,899)} | "
                f"{rnd.choice(['EN_ROUTE','IDLE','STANDBY','PAUSED','OFFLINE'])} | {noise_payload()}")

    # Near-miss 3 (route only) -- single-stage affine decoy (plausible wrong flag).
    rows.append(f"{gen_ts(False)} | {gen_route(True)} | CAB-212 | DISPATCHED | "
                f"{L.affine_enc(WRONG_AFFINE, A, B)}")

    # Near-miss 4 (route only) -- extra noise.
    rows.append(f"{gen_ts(False)} | {gen_route(True)} | CAB-{rnd.randint(101,899)} | "
                f"{rnd.choice(['EN_ROUTE','IDLE','STANDBY','PAUSED','OFFLINE'])} | {noise_payload()}")

    # Filler: every one fails the SHA1 gate, so none can satisfy both gates.
    while len(rows) < 80:
        rows.append(f"{gen_ts(False)} | {gen_route(rnd.random() < 0.5)} | CAB-{rnd.randint(101,899)} | "
                    f"{rnd.choice(['EN_ROUTE','IDLE','STANDBY','PAUSED','OFFLINE'])} | {noise_payload()}")

    rnd.shuffle(rows)
    (out / "taxi_ledger.txt").write_text("\n".join(rows) + "\n", encoding="utf-8")

    # ---- Informational build report (stdout only, not an artifact) --------
    both = sum(1 for r in rows
               if gate_time(r.split("|")[0].strip()) and gate_route(r.split("|")[1].strip()))
    only_one = sum(1 for r in rows
                   if gate_time(r.split("|")[0].strip()) ^ gate_route(r.split("|")[1].strip()))
    print(f"[E02] wrote 80 rows -> {out/'taxi_ledger.txt'}")
    print(f"[E02] dual-gate genuine rows: {both}   single-gate near-misses: {only_one}")
    print(f"[E02] flag = {FLAG}")


if __name__ == "__main__":
    main()
