# M06 · Nightshift Loader — Part 1

**Level:** Medium · **Points:** 100 · **Category:** Malware analysis  
**Location:** Mirror Park · **Focus:** Private packer + rotated key table + custom base + checksum gate

## Mission briefing
A crew's fixer implant was recovered mid-drop in Mirror Park: one opaque blob, the wrapper's scratch notes, and a half-written unpacker somebody abandoned. It is not a real executable and the usual tools learn nothing from it — the container invents its own layout and admits no standard signature. Three reversible layers sit between you and the implant's dispatch order, and the notes confidently nominate the wrong one to undo first. The abandoned stub still runs and cheerfully prints a little phrase the crew left behind for exactly this situation; it is not the drop.

## Objective
Reverse the wrapper and recover the implant's dispatch order plus the token it is meant to hand onward. Nothing in the notes names an algorithm that actually works. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `nightshift_loader.bin`
- `LOADER_NOTES.txt`
- `unpack_stub.py`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
