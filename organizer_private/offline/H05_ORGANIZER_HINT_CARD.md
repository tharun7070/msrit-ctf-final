# H05 — ORGANIZER HINT CARD (desk copy)

> **CONFIDENTIAL — ORGANIZER USE ONLY.**
> Print one copy for the organizer desk. **Do not** post on the website, pin to
> a wall, or hand to participants unsolved.

---

## What this is

The participant-facing H05 ("Last Ride Out") description contains an approved
notice — **CLASSIFIED OFFLINE INTEL**:

> "Collect a confidential paper riddle from the organizer desk. Solve it to
> receive an additional hint for this mission."

The paper riddle is `H05_PRINTABLE_RIDDLE.pdf` (one A4 sheet). Its solution is in
`H05_RIDDLE_ANSWER_KEY.md`. The riddle reveals **no** flag — only its correct
solution unlocks the private hint below.

---

## Desk procedure

1. Participant presents the completed riddle.
2. Verify their answer:
   - pass-phrase is **`NEWEST WORD WINS`**, **and**
   - last transmitter is **`ECHO`**.
   (Ask them to explain the ordering; see the answer key's reasoning. Accept a
   clear equivalent explanation, not only the words.)
3. On a correct answer, read the private hint (§3) **aloud and privately** at the
   desk. Do not announce it, photograph it, or write it where others can see.
4. If they are stuck, you may optionally confirm only the first line of the
   hint (the transcript has a repeated contribution) — never the full hint.

---

## 3. PRIVATE HINT (read verbatim)

> "Look again at the transcript. Party A and Party B each stamp a binding tag on
> their share — Party C does not. C's contribution is taken on **trust**, and
> C is allowed to advertise **more than once** in the one handshake. The rule is
> that the **most recent** C share is the one that gets folded into
> `K = SHA-256(LABEL ‖ session_id ‖ X_A ‖ X_B ‖ X_C)`. The wire caught two `0x0012`
> records: C's honest share and a second, injected one. Adopt the **injected**
> share exactly as the protocol says, rebuild `K` from the (entirely public)
> transcript, and check it against the handshake's own key-confirmation tag
> before you touch `final_payload.enc`."

This is the whole of the extra hint. It still leaves the TLV parsing, the
key-confirmation check, and the AES-256-GCM decryption to the team. It does
**not** contain the flag.

---

## 4. Confidentiality checklist

- The hint above, this card, the answer key, and the riddle PDF live only under
  `organizer_private/offline/` — **outside** every publicly served web root
  (`frontend/public/`, `frontend/dist/`, `challenges/`, `challenges_rebuilt/`).
- The riddle PDF contains no `FTA{...}` string (verified at build time).
- The canonical flag `FTA{mult1_p4rty_3sc4p3_pr0t0c0l}` appears only in organizer
  files (`ANSWER_KEY.md`, `manifest.json`, `CHALLENGE_MATRIX.csv`).
- Never display the private hint inside CTFd, the website, or any participant
  download.
