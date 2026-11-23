# H04 — LEGAL RAGGING (ORGANIZER PRIVATE FILE)

> **CONFIDENTIAL — ORGANIZER USE ONLY.**
> This file contains the actual offline hint, the alternative non-physical logic
> task, completion-verification instructions, and the full reference solution.
> **None of the content below may be shown on the website, printed on participant
> hand-outs, or placed in any publicly downloadable challenge file.**

---

## 1. Challenge identity

| Field | Value |
|---|---|
| CTFd id | `H04` |
| Displayed title | **H04 \| LEGAL RAGGING** |
| Tier / reward | HARD — `$160` |
| Category | Cryptography |
| Location | Fleeca Bank |
| Topic | RSA-CRT fault attack + non-constant-time verify oracle |
| Correct flag | `FTA{rs4_crt_f4ult_l3g4l_r4gg1ng}` |
| Participant files | `bank_gateway.py`, `guest.token`, `AUDIT_BRIEF.txt` |
| Mission card design | **unchanged** — only description text was replaced |

The participant-facing description already contains the approved block
**"SPECIAL OFFLINE HINT — CREW FITNESS CHECK"** (optional, supervised, compliant
10 push-ups *or* the equivalent non-physical logic task in §3). No new buttons or
frontend components were added.

---

## 2. The actual RSA hint (give privately at the desk)

Read **verbatim** (or paraphrase) — do **not** post this anywhere:

> "The gateway's leftover debug route is deterministic when you hand it a `seed`.
> Pin a fixed reference message that starts with `REF:`, then sweep seeds. Most
> answers come back honest; roughly one in ten comes back with `"fault": true`
> and names which CRT half (`Sp` or `Sq`) was mangled. Keep one honest signature
> and one faulty signature **of the same message**. A faulty RSA-CRT signature is
> still correct modulo the *untouched* prime factor, so the difference between
> that bad answer — raised to `e`, minus the message, modulo `n` — and `n` itself
> share exactly one prime factor. That shared factor is `p`; divide and you own
> the key. Then sign the vault order the bank actually wants and submit the
> token. The verifier also leaks a little: it compares byte-by-byte and bails at
> the first mismatch, so a guess whose leading bytes are right takes longer to
> reject — a weaker second confirmation if you want it."

This grants no more than a well-placed nudge; the arithmetic is still the team's
to perform.

---

## 3. Alternative non-physical logic task ("CREW FITNESS CHECK")

A team representative who prefers **not** to do push-ups (or whose circumstances
make physical activity unsuitable) may complete this short deduction instead. It
is supervised, requires no computer or internet, and takes about 3–5 minutes.

**IMPOUND CAGE CODE**

> The crew needs the three-digit code to an impound cage. The intake clerk
> remembers only that:
> 1. the code is **odd**;
> 2. its three digits are **all different**;
> 3. the three digits **add up to 14**;
> 4. among every code satisfying the above, this one is the **largest**.
>
> What is the code?

**Answer: `941`.**

Verification reasoning (organizer): the leading digit must be `9`, so the other
two distinct digits sum to `5`; the trailing digit must be odd for the number to
be odd. The candidate pairs are `(4,1)` → `941`, `(3,2)` → `932`, and `(5,0)` →
`950` (even, rejected). `941` is the largest valid code. Exactly one solution.

---

## 4. Instructions for verifying completion

For the **fitness-check** option:

1. Activity is **voluntary**. Confirm the representative consents and that they
   are physically comfortable. Do **not** pressure, time-shame, or single anyone
   out. Any team member (or the whole team, if they choose) may take part.
2. The activity is done **at the organizer desk, in plain view**. 10 push-ups
   (any form the participant finds comfortable, e.g. knee push-ups count) **or**
   the §3 logic task.
3. On successful completion, read the §2 hint aloud **privately** at the desk.
   Do not announce it, do not photograph it, do not write it on a whiteboard.
4. Compliance: the activity must follow all college/venue rules. If a participant
   is injured, unwell, or unwilling, use the §3 logic task (or simply decline —
   the hint is a bonus, never a requirement to solve the challenge).

For the **logic-task** option:

1. Hand the representative the §3 puzzle (printed on a card kept at the desk).
2. They may think aloud; no calculator or phone.
3. Correct response is `941`. Confirm the reasoning (see §3) rather than only the
   number, then read the §2 hint privately.

---

## 5. Reference solution

Files: `bank_gateway.py` (module + local HTTP endpoints on `127.0.0.1:8420`),
`guest.token` (one valid guest credential), `AUDIT_BRIEF.txt` (in-fiction note).

**Attack steps**

1. Import `bank_gateway` (or use its HTTP routes). Read the public key with
   `gw.public_params()` → `(n, e)`.
2. Choose a fixed probe message that begins with `REF:` (e.g.
   `b"REF:probe:balance:0001"`). Sweep `seed = 0,1,2,…` through `sign_debug`.
   Keep the first response with `"fault": false` (`good`) and the first with
   `"fault": true` (`bad`) **for that same message**.
3. Sanity-check `pow(good, e, n) == m % n`.
4. Fault attack: `p = gcd((pow(bad, e, n) - m) % n, n)`. Because the fault
   corrupted only one CRT half, the bad signature is still correct modulo the
   *other* prime, so `n` and `bad^e - m` share that prime. Then `q = n // p`.
5. Rebuild the private exponent: `d = inverse(e, (p-1)*(q-1))`.
6. Forge a **correctly signed admin vault order**:
   `sig = pow(int.from_bytes(ADMIN_MESSAGE), d, n)` and submit
   `{"role": "admin", "msg": ADMIN_MESSAGE, "sig": hex(sig)}`.
7. `gw.verify(token)` is `True` and `gw.submit(token)` returns the flag
   (the gateway reads it from the `FTA_H04_FLAG` environment variable, so the
   flag is never stored in any participant file).

**Oracle detail used by the reference solver**
`sign_debug` derives `rnd = random.Random(seed)` when a `seed` is supplied, so
`rnd.random() < 0.10` decides whether a fault occurs and `rnd.choice(("Sp","Sq"))`
picks the broken half — fully reproducible.

**Automated checks** (all pass):
- `rebuild_workspace/solve_h04.py` → prints `[H04] PASS -> FTA{rs4_crt_f4ult_l3g4l_r4gg1ng}`.
- `rebuild_workspace/validate_h04.py` → confirms:
  - the reference solver PASSes with the canonical flag;
  - a genuine guest token verifies but is **refused** by `submit` (role gate);
  - an admin token with a wrong signature fails `verify` and `submit`;
  - a genuinely-signed admin message presented under `role="guest"` passes
    `verify` but is **refused** by `submit`.

**Negative controls** (must be rejected):
- Any token whose `sig` is not the true private-key signature of `msg`.
- The correct admin signature presented under a non-admin `role`.
- A wrong flag string (e.g. `FTA{r4gg1ng_r0ugh_but_l3g4l}`) is not the answer.

---

## 6. Confidentiality checklist

- `FTA{rs4_crt_f4ult_l3g4l_r4gg1ng}` appears **only** in organizer files
  (`ANSWER_KEY.md`, `manifest.json`, `CHALLENGE_MATRIX.csv`); never in
  `challenges_rebuilt/`, `frontend/public/`, or `frontend/dist/`.
- `bank_gateway.py` holds the CRT key material in an **obfuscated keystore** and
  reads the flag from the environment — no plaintext flag anywhere in the
  participant artifact.
- The §2 hint, the §3 logic task and its answer, and this file are organizer-only.
