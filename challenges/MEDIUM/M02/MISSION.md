# M02 · Airport Ghost Flight

**Level:** Medium · **Points:** 100 · **Category:** Network forensics  
**Location:** Los Santos International Airport · **Focus:** IPv4 fragmentation + nested frames + scoped seal + nonce-keyed mask

## Mission briefing
LSIA's tower talks to a plane radar insists isn't there. The capture does not even hand you whole packets: each message is shattered across IPv4 fragments you must reassemble before a single protocol byte makes sense. Inside, two layers of framing hide a scoped seal that covers only part of each frame, and the mask is keyed by a session nonce carried once, on the first genuine message. A decoy group boasts a valid whole-frame checksum and reassembles to a flag that is a lie, and the outer ordering field is bait.

## Objective
Reassemble the fragmented datagrams, walk both framing layers, harvest the session nonce, and reconstruct the ghost flight's callsign. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `airport_traffic.pcap`
- `MANIFEST.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
