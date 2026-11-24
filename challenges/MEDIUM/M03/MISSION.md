# M03 · LSPD Midnight Audit

**Level:** Medium · **Points:** 100 · **Category:** Log forensics  
**Location:** Los Santos Police Department · **Focus:** Keyed chain + hidden salt + checkpoint roots + triply-nested delta

## Mission briefing
LSPD's overnight auth log claims to be tamper-evident: every line is chained by a keyed hash and periodic roots pin each block — but the salt is nowhere in the file, so a plain unkeyed recomputation cheerfully 'verifies' the forgeries. Two blocks are broken, not one. The sidecar delta that holds the originals is nested three deep, and a long run of easy-looking entries is bait that collapses to a flag that is not this audit's.

## Objective
Recover the salt from the checkpoint roots, repair every broken block, and derive the encoded flag from a cross-field predicate. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `lspd_auth.log`
- `audit_delta.bin`
- `CHAIN_SPEC.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
