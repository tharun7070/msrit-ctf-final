# M05 · Debugging the Dispatch

**Level:** Medium · **Points:** 100 · **Category:** Programming  
**Location:** Lester's Hideout · **Focus:** Two-structure race + dual-bug stage 2 + final wrap

## Mission briefing
Lester's dispatcher rebuilds a message from unordered packets, but it loses packets under load and its output is still wrapped in more of its own mistakes. The loss is a race across two shared structures, so locking a single increment will not be enough. What the fixed dispatcher emits is another program with two independent bugs, and even a correctly fixed program leaves the result wrapped one more time.

## Objective
Fix the dispatcher so it runs deterministically, then repair the two independent bugs in the program it produces, and unwrap the final layer. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `broken_dispatch.py`
- `dispatch_packets.json`
- `README.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
