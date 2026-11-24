# E08 · Dead Drop Uplink

**Level:** Easy · **Points:** 50 · **Category:** Network forensics  
**Location:** La Mesa · **Focus:** Custom UDP sessions + CRC gate + keyed XOR

## Mission briefing
A tow-truck dead drop pinged a cell tower in La Mesa and vanished. The capture holds two interleaved sessions with identical framing; exactly one is real, and the spec sheet you were handed points at the wrong one — a replayed decoy whose fragments reassemble into a flag that isn't the drop. The genuine session's key rides in a single control uplink, folded twice.

## Objective
Pick the genuine session, validate its fragments, recover the session key, and reconstruct the drop. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `dead_drop.pcap`
- `UPLINK_SPEC.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
