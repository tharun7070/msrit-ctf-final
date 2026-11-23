#!/usr/bin/env python3
"""E02 — Vinewood Shift Change. Generator (private).
80-row ledger; the genuine row is the one whose timestamp SHA-1 ends in 'a3';
payload is affine(a=7,b=11); a decoy row decrypts under Caesar-5 to a fake flag."""
import hashlib, random, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

FLAG = L.FLAGS["E02"]
A, B = 7, 11

def main():
    out = L.out_dir("E02")

    # 400-char English block encrypted with the affine cipher -> frequency analysis aid
    sample = (
        "The midnight fleet leaves Vinewood station every twenty minutes hauling cash "
        "from the casino vault. Drivers maintain radio silence through the hills and "
        "verify every drop coordinate before they move. Lester warned that private "
        "security patrols have increased along the freeway interchanges tonight. Keep "
        "all telemetry packets recorded in the dispatch log for the end of shift audit "
        "and asset reconciliation at dawn sharp."
    )[:400]
    (out / "frequency_sample.bin").write_bytes(L.affine_enc(sample, A, B).encode())

    rnd = random.Random(0x1337E02)

    def ts(different_from=None):
        while True:
            t = f"2026-11-20T{rnd.randint(0,23):02d}:{rnd.randint(0,59):02d}:{rnd.randint(0,59):02d}.{rnd.randint(100,999)}Z"
            if t == different_from:
                continue
            if hashlib.sha1(t.encode()).hexdigest().endswith("a3"):
                return t

    def ts_bad(exclude):
        while True:
            t = f"2026-11-20T{rnd.randint(0,23):02d}:{rnd.randint(0,59):02d}:{rnd.randint(0,59):02d}.{rnd.randint(100,999)}Z"
            if t in exclude:
                continue
            if not hashlib.sha1(t.encode()).hexdigest().endswith("a3"):
                return t

    good_ts = ts()
    used = {good_ts}
    rows = [f"{good_ts} | ROUTE-99-ALPHA | CAB-104 | DISPATCHED | {L.affine_enc(FLAG, A, B)}"]

    decoy_ts = ts_bad(used); used.add(decoy_ts)
    rows.append(f"{decoy_ts} | ROUTE-05-BRAVO | CAB-077 | TERMINATED | {L.caesar_enc('FTA{wrong_route}', 5)}")
    while len(rows) < 80:
        t = ts_bad(used); used.add(t)
        noise = f"TRANSIT_NOTE_{rnd.randint(1000,9999)}_SIGNAL_LOSS_{rnd.randint(100,999)}"
        rows.append(f"{t} | ROUTE-{rnd.randint(10,89)} | CAB-{rnd.randint(101,899)} | "
                    f"{rnd.choice(['EN_ROUTE','IDLE','STANDBY','PAUSED','OFFLINE'])} | "
                    f"{L.caesar_enc(noise, rnd.choice([3,5,9,17]))}")
    rnd.shuffle(rows)
    (out / "taxi_ledger.txt").write_text("\n".join(rows) + "\n", encoding="utf-8")
    print(f"[E02] wrote 80 rows -> {out/'taxi_ledger.txt'}")
    print(f"[E02] flag = {FLAG}")

if __name__ == "__main__":
    main()
