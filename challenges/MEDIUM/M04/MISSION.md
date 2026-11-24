# M04 · Underground XOR Radio

**Level:** Medium · **Points:** 100 · **Category:** Cryptography  
**Location:** Underground Market · **Focus:** Three interleaved LFSRs + header lane offset + partial KPA + lane transpose

## Mission briefing
A black-market radio burst is only a few hundred bytes, but its keystream came from three machines, multiplexed in fixed-length bursts whose starting lane is written in the one part of the packet that is not encrypted. Only a sliver of a known header was captured, so one register must be reconstructed by linear algebra rather than assumed. A fixed lane transpose sits between the XOR and the wire, and the signal spec is bait: it lists parameters that are confidently wrong.

## Objective
Read the sync header, de-multiplex the three generators, recover each register, undo the transpose, and decrypt the packet. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `radio_packet.bin`
- `keystream_sample.bin`
- `SIGNAL_SPEC.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
