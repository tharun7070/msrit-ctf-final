# H05 · Last Ride Out

**Level:** Hard · **Points:** 160 · **Category:** Multilayer cryptography  
**Location:** Final Getaway · **Focus:** 4-party agreement break + HKDF + nested AES

## Mission briefing
The getaway's final message crossed a four-party key agreement. A captured transcript and the encrypted payload survive, and two of the four seats were never checked — read the framing and you will see which contributions are bound and which are taken on faith and re-advertised. The shared secret is not a neat sum but a weighted product, so sitting in an unchecked seat means solving for a value, not merely choosing one. The payload is nested twice, and some of the confirmations are decoys.

CLASSIFIED OFFLINE INTEL

Collect a confidential paper riddle from the organizer desk. Solve it to receive an additional hint for this mission.

## Objective
Parse the transcript, identify the unauthenticated seats, steer the weighted session key, and decrypt the nested payload. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `intercept.bin`
- `final_payload.enc`
- `ESCAPE_PROTOCOL.md`
- `FORMAT_SPEC.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
