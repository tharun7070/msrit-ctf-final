# H01 · Zancudo Deadbolt

**Level:** Hard · **Points:** 160 · **Category:** Reverse engineering  
**Location:** Fort Zancudo Military Base · **Focus:** Anti-analysis traps + chained VMs + runtime-keyed vault

## Mission briefing
Fort Zancudo's Hangar 13 deadbolt runs firmware nobody has logged into since the desert went sideways. Your only copy is a stripped native binary that refuses to be watched and asks for a single operator passphrase. It is under no obligation to tell you the truth about why it says no — and when it is being watched, it lies with a straight face and a confident release banner. Behind the flattened dispatchers sit chained virtual machines, and the station's tables are not sitting in plaintext in the file. Interrogate the station exactly the way it expects, or it will hand you a flag of its own invention and walk you into a dead end.

## Objective
Defeat the anti-analysis traps, reverse the chained virtual machines, and recover the single operator passphrase, submitted as one flag in the form FTA{...}. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `zancudo_gate`
- `OPERATIONS.txt`
- `ENGINEER_NOTE.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
