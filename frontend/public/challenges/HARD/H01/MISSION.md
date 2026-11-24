# H01 · Zancudo Deadbolt

**Level:** Hard · **Points:** 160 · **Category:** Reverse engineering  
**Location:** Fort Zancudo Military Base · **Focus:** Anti-analysis traps + chained VMs + runtime-keyed vault

## Mission briefing
Fort Zancudo's Hangar 13 deadbolt runs firmware nobody has logged into since the desert went sideways. Your only copy is a stripped native binary that refuses to be watched and asks for a single operator passphrase. It is under no obligation to tell you the truth about why it says no — and when it is being watched, it lies with a straight face and a confident banner. Behind the flattened dispatchers are two chained virtual machines, and the station's tables are not sitting in plaintext in the file.

## Objective
Defeat the anti-analysis traps, reverse both virtual machines, and recover the operator passphrase. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `zancudo_gate`
- `OPERATIONS.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
