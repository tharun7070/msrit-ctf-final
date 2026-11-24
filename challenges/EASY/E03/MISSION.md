# E03 · Sandy Shores Hidden Stash

**Level:** Easy · **Points:** 50 · **Category:** Linux forensics  
**Location:** Sandy Shores · **Focus:** ext2 recovery + multi-byte keyed mask

## Mission briefing
The Sandy Shores safehouse yielded a dead laptop, imaged before the drive could be wiped. Several files were deleted, and only one stash is genuine — the others are the kind of bait that rewards a shallow carve. The real payload is masked with a repeating key whose every byte is computed from two separate fields on a surviving dock-worker log, and then wrapped in two more reversible layers before it is readable. The deletion order tells you nothing; a wasted carve tells you a lot.

## Objective
Recover the genuine deleted payload from the image, identify it among the decoys, and reverse its full masking chain. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `safehouse.img`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
