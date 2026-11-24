# E12 · Relay Archive

**Level:** Easy · **Points:** 50 · **Category:** Network forensics  
**Location:** Grapeseed · **Focus:** Offline relay archive + dual-carrier merge + decoy replays

## Mission briefing
The same Ghost Relay keeps a buffer for crews working dark, and what you have here is the relay's off-air copy of what it was holding when it went quiet. It mixes a genuine parcel with old fragments it left on the legacy replay carrier, and the notes shipped with the dump are a plant — they point you at the wrong port and hand you two bait flags by name. The genuine parcel remembers the relay it came from: it is stamped with the very session tag from the Ghost Relay capture, and it is the only parcel in the dump spread across two carriers rather than one.

## Objective
Identify the genuine parcel in the archive, reassemble it, and submit the flag. It is directly related to the capture from Ghost Relay. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `relay_archive.pcap`
- `COURIER_RELAY.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
