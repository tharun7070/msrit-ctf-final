# M04 · Underground XOR Radio

**Level:** Medium · **Points:** 100 · **Category:** Cryptography  
**Location:** Underground Market · **Focus:** Three interleaved LFSRs + header lane offset + partial KPA + lane transpose

## Mission briefing
A black-market radio burst is only a few hundred bytes, but its keystream came from three machines taking turns in fixed-length bursts, and the schedule's starting lane and burst length are written in the one part of the packet that is not encrypted. Only the first sliver of a known header survived capture (the recorder zero-filled the rest), so one register must be reconstructed by linear algebra rather than assumed. Masking is not the whole wire: before transmission the frame is wrapped twice more, both wraps keyed off the cleartext header, over a fixed-width lane transpose. The recovered signal notes are bait as much as they are intel — they mix genuine captured fields with an unverified block that describes a superseded firmware revision and confidently wrong parameters, and the on-duty analyst's note pushes you toward that older net and an answer it hands you far too easily.

## Objective
Read the cleartext sync header, de-multiplex the three generators from the surviving known-plaintext sample, recover every register, undo the full post-mask chain (wash, spin and the lane transpose) and recover the live payload of radio_packet.bin, submitted as one flag in the form FTA{...}. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `radio_packet.bin`
- `keystream_sample.bin`
- `SIGNAL_SPEC.txt`
- `OPERATOR_NOTE.txt`
- `legacy_burst.bin`
- `branchB_candidate.bin`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
