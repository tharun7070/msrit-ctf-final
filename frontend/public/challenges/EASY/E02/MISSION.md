# E02 · Vinewood Shift Change

**Level:** Easy · **Points:** 50 · **Category:** Cryptography  
**Location:** Vinewood Boulevard · **Focus:** Dual fingerprint gate + transposition-over-substitution

## Mission briefing
Vinewood's night-shift taxi ledger is almost all legitimate fares. One car was never meant to be logged and its manifest line is wrapped in a shift nobody wrote down. A decoy line decrypts perfectly under the lazy assumption and leads nowhere. Worse, the line is not merely substituted: a transposition sits on top, so a single-stage break returns scrambled text. The sample block is rigged the same way, so the textbook frequency attack will confidently hand you a parameter pair that is simply wrong.

## Objective
Find the genuine intercepted line, unwind both stages of its cipher, and recover the manifest. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `taxi_ledger.txt`
- `frequency_sample.bin`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
