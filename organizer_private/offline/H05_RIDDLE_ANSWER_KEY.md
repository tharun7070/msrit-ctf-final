# H05 PRINTABLE RIDDLE — ANSWER KEY

> **CONFIDENTIAL — ORGANIZER USE ONLY.**
> Companion to `H05_PRINTABLE_RIDDLE.pdf`. Do not hand this to participants and
> do not place it in any publicly served directory.

---

## The riddle (recap)

Three couriers — **RICO**, **HALO**, **ECHO** — each make exactly one relay
transmission, from three different stations (**ELYSIAN ISLAND**, **DEL PERRO
PIER**, **VINEWOOD TOWER**) in three different slots (1 = first … 3 = last).

Clues:
1. RICO transmitted from ELYSIAN ISLAND.
2. HALO's call was the second transmission of the night.
3. The DEL PERRO PIER transmission happened immediately after the ELYSIAN ISLAND one.
4. ECHO was not the first to transmit.

Relay key: ELYSIAN ISLAND → **NEWEST** · DEL PERRO PIER → **WORD** ·
VINEWOOD TOWER → **WINS**.

Answer the participants must return: the three-word pass-phrase read in
transmission order, plus the courier who transmitted last.

---

## Unique solution

| Slot | Courier | Relay | Relay code-word |
|------|---------|-------|-----------------|
| 1 (first) | **RICO** | ELYSIAN ISLAND | **NEWEST** |
| 2 (middle) | **HALO** | DEL PERRO PIER | **WORD** |
| 3 (last) | **ECHO** | VINEWOOD TOWER | **WINS** |

**Pass-phrase: `NEWEST WORD WINS`**
**Last transmitter: `ECHO`**

### Reasoning

1. Clue 1 fixes RICO → ELYSIAN ISLAND.
2. Clue 3 requires DEL PERRO PIER to be the slot immediately after ELYSIAN
   ISLAND. So ELYSIAN ISLAND is slot 1 or slot 2.
3. If ELYSIAN ISLAND were slot 2, then slot 2 would belong to RICO — but clue 2
   says slot 2 belongs to HALO. Contradiction. Hence ELYSIAN ISLAND = slot 1 and
   DEL PERRO PIER = slot 2.
4. Clue 2 → HALO is slot 2, so HALO → DEL PERRO PIER.
5. The only relay left for ECHO is VINEWOOD TOWER (slot 3); clue 4 (ECHO is not
   first) is automatically satisfied since RICO holds slot 1.
6. Read the relay code-words in slot order 1 → 2 → 3:
   `NEWEST` + `WORD` + `WINS` = **`NEWEST WORD WINS`**.

---

## Independence / uniqueness proof

Brute-force enumeration over all relay permutations (3! = 6) × slot
permutations (3! = 6) = **36** candidate nights, filtered by the four clues,
yields **exactly one** solution — the table above. Reproduce with:

```python
import itertools
C = ['RICO', 'HALO', 'ECHO']; R = ['E', 'D', 'V']; sols = []
for r in itertools.permutations(R):
    for s in itertools.permutations([1, 2, 3]):
        ro = dict(zip(C, r)); so = dict(zip(C, s)); inv = {v: k for k, v in ro.items()}
        if ro['RICO'] == 'E' and so['HALO'] == 2 \
           and so[inv['D']] == so[inv['E']] + 1 and so['ECHO'] != 1:
            sols.append((ro, so))
print(len(sols))          # -> 1
print(sols)               # -> [{RICO:E, HALO:D, ECHO:V}, {RICO:1, HALO:2, ECHO:3}]
```

Properties checked:
- **Unique** answer (1 of 36) — objectively verifiable.
- **No internet / no computer** required (pure deduction, ~3–5 min).
- **No flag revealed** — the sheet never contains `FTA{...}` or any key bytes.
- The "faint earlier call from ECHO that was cut off" line is deliberate
  misdirection reinforcing the protocol theme ("the most recent word wins");
  it does not affect the solution.

---

## Why this is the H05 hint (private mapping)

The riddle's rule *"if the wire catches the same courier twice, only the most
recent call is authoritative"* deliberately mirrors the real ESCAPE-3 flaw.
Handing a team the pass-phrase is the trigger for the organizer to read the
private hint on `H05_ORGANIZER_HINT_CARD.md`:

> Party C's contribution is **unauthenticated** and is **accepted verbatim**;
> when C advertises a share **twice**, the **latest** one is the one used to
> build the session key — so use the injected share and rebuild the key from the
> public transcript.

The riddle itself never states this; only the organizer card does.
