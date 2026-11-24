# M08 · Nightshift C2 — Part 3

**Level:** Medium · **Points:** 100 · **Category:** Malware analysis  
**Location:** Port of Los Santos · **Focus:** Stateful C2 protocol + HMAC-gated chained frames + plaintext decoy broadcast

## Mission briefing
The last piece is the crew's command channel as it crossed the wire, lifted off a Port of Los Santos relay. It is not HTTP and it is not polite: every real message is an authenticated frame, the channel is salted with replays and at least one tampered frame, and a frame only decrypts in its true position — a later frame is locked by the one the crew already accepted. The capture also carries a plaintext diagnostic the implant let slip; it names an archived flag that will be refused on sight. Two endpoints appear on the wire, and the one the notes favour is a retired session that carries no key you hold.

## Objective
Authenticate the genuine session using the endpoint and session id from Part 2, walk the frames in order, and recover the exfiltrated flag. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `nightshift_c2.pcap`
- `C2_NOTES.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
