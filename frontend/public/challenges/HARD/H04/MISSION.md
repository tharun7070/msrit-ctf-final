# H04 · LEGAL RAGGING

**Level:** Hard · **Points:** 160 · **Category:** Cryptography  
**Location:** Fleeca Bank · **Focus:** RSA-CRT fault attack + timing oracle

## Mission briefing
Fleeca's mock gateway signs bank orders with RSA-CRT and keeps a 'debug' signing route it was never supposed to ship. Occasionally that route lies about one of its two internal halves. Two signatures of the same order are enough to undo the key — and a second weakness in verification confirms the forgery.

SPECIAL OFFLINE HINT — CREW FITNESS CHECK

Visit the organizer desk to unlock an optional hint. One willing team representative can complete 10 push-ups, or choose an equivalent non-physical logic task. The organizer will provide the hint privately. This activity is optional, supervised and compliant with college rules — there is no pressure, humiliation or compulsory physical activity.

## Objective
Recover the signing key from the faulty debug route, forge an admin order, and unlock the vault. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `bank_gateway.py`
- `guest.token`
- `AUDIT_BRIEF.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
