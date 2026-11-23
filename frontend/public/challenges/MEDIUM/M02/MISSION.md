# M02 · Airport Ghost Flight

**Level:** Medium · **Points:** 100 · **Category:** Network forensics  
**Location:** Los Santos International Airport · **Focus:** Custom binary protocol + CRC32 gating

## Mission briefing
LSIA's tower talks to a plane radar insists isn't there. The capture is raw wire, not a tidy protocol tree: the tower's own packets ride inside ordinary TCP, sealed with a checksum, numbered, and masked with that very seal. Most of them are fakes.

## Objective
Reconstruct the ghost flight's callsign from the capture. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `airport_traffic.pcap`
- `MANIFEST.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
