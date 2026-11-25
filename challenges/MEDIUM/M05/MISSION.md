# M05 · Debugging the Dispatch

**Level:** Medium · **Points:** 100 · **Category:** Programming  
**Location:** Lester's Hideout · **Focus:** Serialised race + three-bug stage 2 + stage-3 unwrap

## Mission briefing
The depot dispatch node at the Los Santos freight relay, broken_dispatch.py, fans 1200 tagged packets across eight worker threads and seals a manifest to out.bin -- except the seal it writes never balances, because the workers race across THREE shared process-wide structures (a per-lane tally, a running ledger and a running mix). The sealed manifest carries two masked programs -- a reconciler and an assembler -- that only unmask once the node's final dispatched/ledger/mix triple is correct. The reconciler is miscompiled in more than one independent place and its second lane is built on its first, so a single clean pass looks plausible and is still wrong. The assembler refuses to return the dispatch value from one lane alone. A retired operator's note ships in the package and is happy to hand you a short cut; it is not telling the truth. Recover the genuine dispatched flag.

## Objective
Repair the depot node so its sealed manifest is correct, unmask and fix the embedded reconciler, then combine BOTH lane runs through the assembler to recover the true dispatched flag -- ignoring every planted shortcut and fake. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `broken_dispatch.py`
- `dispatch_packets.json`
- `README.txt`
- `recovery_note.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
