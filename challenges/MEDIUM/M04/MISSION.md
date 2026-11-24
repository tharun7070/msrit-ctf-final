# M04 · Underground XOR Radio

**Level:** Medium · **Points:** 100 · **Category:** Cryptography  
**Location:** Underground Market · **Focus:** Interleaved LFSRs + partial KPA + lane transpose

## Mission briefing
A black-market radio burst is only a few hundred bytes, but its keystream came from two machines, not one, and they are multiplexed byte-by-byte on the wire. Only part of a known header was captured alongside it, and a fixed lane transpose sits between the XOR and the bytes you see. The signal spec is bait: it lists parameters that are confidently wrong.

## Objective
De-multiplex the two generators, recover both from the partial sample, undo the transpose, and decrypt the packet. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `radio_packet.bin`
- `keystream_sample.bin`
- `SIGNAL_SPEC.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
