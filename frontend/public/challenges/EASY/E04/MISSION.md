# E04 · Del Perro Camera Roll

**Level:** Easy · **Points:** 50 · **Category:** Steganography  
**Location:** Del Perro Pier · **Focus:** Gated bit-plane stego + geometry-keyed mask

## Mission briefing
Del Perro's pier camera caught nothing suspicious, but the file is heavier than its picture deserves. The payload does not ride in every pixel and not in the lowest plane — only certain 'blessed' pixels carry it, and a blanket low-bit sweep returns bait. What you finally extract is masked with a key built from the image's own geometry plus a logged salt, and then wrapped twice, in a decompressor and a text encoding from a forgotten decade.

## Objective
Extract the hidden message and reverse every layer, ignoring the traps placed for the obvious tool. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `camera_roll.png`
- `README.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
