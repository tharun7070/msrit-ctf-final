#!/usr/bin/env python3
"""E01 — Lester's Pager Panic. Generator (private).
200-row dispatch.csv; genuine rows satisfy (col_A*col_B)%col_C==7; payloads are
custom base-41; order = (parity of col_D asc, col_E desc)."""
import csv, random, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import lib_fta as L

FLAG = L.FLAGS["E01"]

def main():
    chunks = [FLAG[i:i + 7].encode() for i in range(0, len(FLAG), 7)]
    # ordering slots: (col_D, col_E) — parity 0 rows first (desc E), then parity 1 (desc E)
    n = len(chunks)
    half = (n + 1) // 2
    slots = []
    for k in range(half):
        slots.append((100 + 2 * k, 950 - 130 * k))        # parity 0
    for k in range(n - half):
        slots.append((101 + 2 * k, 910 - 130 * k))        # parity 1

    rnd = random.Random(0x1337E01)
    rows = []
    for i, ch in enumerate(chunks):
        while True:
            a, b, c = rnd.randint(10, 500), rnd.randint(10, 500), rnd.randint(30, 200)
            if (a * b) % c == 7:
                break
        d, e = slots[i]
        rows.append([f"PKT-{rnd.randint(10000, 99999)}", a, b, c, d, e, L.base41_encode(ch)])
    while len(rows) < 200:
        while True:
            a, b, c = rnd.randint(10, 500), rnd.randint(10, 500), rnd.randint(30, 200)
            if (a * b) % c != 7:
                break
        payload = "".join(rnd.choice(L.BASE41_ALPHABET) for _ in range(rnd.randint(5, 9)))
        rows.append([f"PKT-{rnd.randint(10000, 99999)}", a, b, c,
                     rnd.randint(10, 999), rnd.randint(100, 999), payload])
    rnd.shuffle(rows)

    p = L.out_dir("E01") / "dispatch.csv"
    with p.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["packet_id", "col_A", "col_B", "col_C", "col_D", "col_E", "payload"])
        w.writerows(rows)
    print(f"[E01] wrote {len(rows)} rows -> {p}")
    print(f"[E01] flag = {FLAG}")

if __name__ == "__main__":
    main()
