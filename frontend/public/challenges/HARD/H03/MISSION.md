# H03 · Impound Evidence Matryoshka

**Level:** Hard · **Points:** 160 · **Category:** Multi-stage forensics  
**Location:** Los Santos Police Department · **Focus:** 7-layer chained stego + cryptographic nesting

## Mission briefing
LSPD impounded a camera with a single frame and a note claiming the case was closed. Seven layers deep, three of them are bait. A blanket low-bit dump is poisoned; the note's frequency table gives the stride, not the codes; and each later shell is keyed by something recovered from the shell before it, so you cannot start in the middle. Only one path yields something that runs.

## Objective
Peel the chained layers, discard the decoys, and run the final stage to reveal the flag. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `impound_camera.png`
- `EVIDENCE_NOTE.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
