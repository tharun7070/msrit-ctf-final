# M05 · Debugging the Dispatch

**Level:** Medium · **Points:** 100 · **Category:** Programming  
**Location:** Lester's Hideout · **Focus:** Serialised race + three-bug stage 2 + stage-3 unwrap

## Mission briefing
Lester's dispatcher rebuilds a message from unordered packets, but under load it loses packets through a race across two shared structures — locking a single counter is not enough. The fixed dispatcher then emits a program with three independent bugs, the third of which only fires when a length lands on a four-byte boundary, so testing one input misleads you. Even a fully correct program leaves the result wrapped one more time. A partial fix prints ARCHIVED_VALUE, and a decoy sits in the notes.

## Objective
Fix the dispatcher race so it runs deterministically, repair all three bugs in the program it produces, and unwrap the final layer. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `broken_dispatch.py`
- `dispatch_packets.json`
- `README.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
