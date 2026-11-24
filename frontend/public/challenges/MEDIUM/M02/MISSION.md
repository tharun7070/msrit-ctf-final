# M02 · Airport Ghost Flight

**Level:** Medium · **Points:** 100 · **Category:** Network forensics  
**Location:** Los Santos International Airport · **Focus:** Nested frames + scoped seal + sequence-keyed mask

## Mission briefing
LSIA's tower talks to a plane radar insists isn't there. The capture is raw wire with two layers of framing: the tower's own packets ride inside ordinary TCP, and inside those sits yet another frame with its own magic. The seal is computed over part of each frame, not all of it, and the payload is masked by the inner sequence rather than by the seal. Most packets are fakes, and the outer ordering field is a deliberate lie.

## Objective
Walk both framing layers, keep only the genuinely-sealed messages, and reconstruct the ghost flight's callsign. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `airport_traffic.pcap`
- `MANIFEST.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
