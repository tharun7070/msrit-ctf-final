# M05 · Debugging the Dispatch

**Level:** Medium · **Points:** 100 · **Category:** Programming  
**Location:** Lester's Hideout · **Focus:** Concurrency race + 32-bit checksum

## Mission briefing
Lester's dispatcher is meant to rebuild a message from unordered packets, but it loses some under load, and its output is still wrapped in two more layers of its own mistakes. Two programs, two bugs, one flag.

## Objective
Fix the dispatcher, run it deterministically, then repair the second-stage program it produces. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `broken_dispatch.py`
- `dispatch_packets.json`
- `README.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
