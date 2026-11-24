# E01 · Lester’s Pager Panic

**Level:** Easy · **Points:** 50 · **Category:** Cryptography  
**Location:** Lester's Hideout · **Focus:** Dual modular filter + per-row stream permutation

## Mission briefing
Lester's pager dumped a whole night of dispatch chatter and only a sliver of it is his. The genuine courier packets never announce themselves: a real row must satisfy more than one arithmetic secret at once, and the ones that satisfy only one are poisoned. Even the wording is hostile — the payloads use a private alphabet that is then scrambled again, row by row, by a rule the salvaged decoder will not hand you. The drop is also re-ordered under a third, hidden key and padded with a marker you have to notice before you can trust a single byte.

## Objective
Recover the single dispatch message. Nothing in the log names the columns, the permutation, or the order. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `dispatch.csv`
- `decoder`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
