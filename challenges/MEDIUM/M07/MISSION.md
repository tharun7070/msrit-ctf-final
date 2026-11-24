# M07 · Nightshift Config — Part 2

**Level:** Medium · **Points:** 100 · **Category:** Malware analysis  
**Location:** Elysian Island · **Focus:** Smeared RAM XOR key + trap nibble + keyed KDF/HMAC + decoy section

## Mission briefing
The fixer stashed its configuration beside a scrap of process memory pulled from a dockyard terminal at Elysian Island. The key was never stored whole: four allocations in the heap slice hold it split apart, and a fifth looks exactly like the ones you want but belongs to a build the crew retired — combining it yields a key that opens nothing. The config is double-locked, and one lock will not even answer unless you already carry the dispatch order from the loader. One of the two sealed sections is genuine and one is a planted twin for the retired key; the notes swear the wrong one is live.

## Objective
Rebuild the smeared key from the live buffers only, unlock the config with the dispatch order from Part 1, and read the C2 endpoint and session id it keeps for the next stage. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `nightshift_config.bin`
- `ram_slice.bin`
- `CONFIG_NOTES.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
