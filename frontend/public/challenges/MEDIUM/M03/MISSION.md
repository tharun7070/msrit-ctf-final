# M03 · LSPD Midnight Audit

**Level:** Medium · **Points:** 100 · **Category:** Log forensics  
**Location:** Los Santos Police Department · **Focus:** Keyed hash chain + block checkpoints + nested delta

## Mission briefing
LSPD's overnight auth log claims to be tamper-evident: every line is chained to the previous one by a hash, and periodic checkpoints root each block. Three lines are lies. A plain unkeyed recomputation will 'verify' those forgeries, which is exactly the trap — the chain is keyed by a salt you must find, and both the chain and the block roots must agree. A sidecar delta holds what the originals should have said, but it is nested, and the flag is not a tidy pairwise XOR of adjacent characters.

## Objective
Verify the keyed chain and its checkpoints, repair the forgeries via the nested delta, and derive the encoded flag from a cross-field predicate. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `lspd_auth.log`
- `audit_delta.bin`
- `CHAIN_SPEC.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
