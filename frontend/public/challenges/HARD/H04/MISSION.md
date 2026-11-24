# H04 · LEGAL RAGGING

**Level:** Hard · **Points:** 160 · **Category:** Cryptography  
**Location:** Fleeca Bank · **Focus:** Blinded RSA-CRT fault + timing oracle + freshness gate

## Mission briefing
Fleeca's mock gateway signs bank orders with RSA-CRT and keeps a 'debug' signing route it was never supposed to ship. That route blinds what it signs and, occasionally, lies about one of its two internal halves — rarely, and in either half. A second route leaks, byte by byte, a live nonce the vault order must carry, and the verifier now also demands the right role and a fresh timestamp. Two signatures are no longer enough on their own.

SPECIAL OFFLINE HINT — CREW FITNESS CHECK

Visit the organizer desk to unlock an optional hint. One willing team representative can complete 10 push-ups, or choose an equivalent non-physical logic task. The organizer will provide the hint privately. This activity is optional, supervised and compliant with college rules — there is no pressure, humiliation or compulsory physical activity.

## Objective
Recover the signing key from the blinded, faulty debug route, satisfy the nonce and freshness gates, forge an admin order, and unlock the vault. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `bank_gateway.py`
- `guest.token`
- `AUDIT_BRIEF.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
