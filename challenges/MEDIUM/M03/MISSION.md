# M03 · LSPD Midnight Audit

**Level:** Medium · **Points:** 100 · **Category:** Log forensics  
**Location:** Los Santos Police Department · **Focus:** Keyed chain + hidden salt + checkpoint roots + triply-nested delta

## Mission briefing
Nightshift closes in two hours and Dispatch wants the audit signed off. The LSPD automated audit bus dumped a thousand dispatch records into lspd_auth.log, but three of them were rewritten after the fact. You are handed the tamper-evident chain, a sealed sidecar (audit_delta.bin), the on-disk specification -- and, because someone meant well, an unofficial desk note. Recover the altered records, bring the chain back into agreement, and hand Dispatch the real audit flag.

## Objective
Repair the keyed, block-dependent audit chain, open both sealed regions of audit_delta.bin in the correct order, and submit the flag that satisfies the spec's acceptance predicate and final sealed unwrap. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `lspd_auth.log`
- `audit_delta.bin`
- `CHAIN_SPEC.txt`
- `OPS_NOTE.txt`
- `flash_backup.bin`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
