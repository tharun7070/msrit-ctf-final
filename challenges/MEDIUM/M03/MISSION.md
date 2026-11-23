# M03 · LSPD Midnight Audit

**Level:** Medium · **Points:** 100 · **Category:** Log forensics  
**Location:** Los Santos Police Department · **Focus:** Hash-chain verification + tamper reconstruction

## Mission briefing
LSPD's overnight auth log claims to be tamper-evident: every line is chained to the previous one by a hash. Three lines are lies, and the chain knows it. A sidecar delta holds what the originals should have said.

## Objective
Verify the chain, locate and repair the forgeries, and extract the encoded flag. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `lspd_auth.log`
- `audit_delta.bin`
- `CHAIN_SPEC.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
