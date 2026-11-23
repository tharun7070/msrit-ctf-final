# H05 · Last Ride Out

**Level:** Hard · **Points:** 160 · **Category:** Multilayer cryptography  
**Location:** Final Getaway · **Focus:** 3-party protocol break + AES-GCM

## Mission briefing
The getaway's final message crossed a three-party key agreement. A captured transcript and the encrypted payload survive, and the protocol has one seat nobody ever checked. Sit in it, and the session key becomes yours to choose.

CLASSIFIED OFFLINE INTEL

Collect a confidential paper riddle from the organizer desk. Solve it to receive an additional hint for this mission.

## Objective
Parse the transcript, find the unchecked contribution, bias the session key, and decrypt the payload. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `intercept.bin`
- `final_payload.enc`
- `ESCAPE_PROTOCOL.md`
- `FORMAT_SPEC.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
