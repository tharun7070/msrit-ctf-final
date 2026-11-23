# M04 · Underground XOR Radio

**Level:** Medium · **Points:** 100 · **Category:** Cryptography  
**Location:** Underground Market · **Focus:** LFSR keystream + Berlekamp-Massey

## Mission briefing
A black-market radio burst is only a few hundred bytes, but its keystream came from a machine, not a passphrase. A short sample of a known header was captured alongside it — enough to rebuild the generator itself.

## Objective
Reconstruct the keystream generator and decrypt the packet. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `radio_packet.bin`
- `keystream_sample.bin`
- `SIGNAL_SPEC.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
