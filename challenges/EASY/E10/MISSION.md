# E10 · Towing Yard Ignition

**Level:** Easy · **Points:** 50 · **Category:** Reverse engineering  
**Location:** El Burro Heights · **Focus:** Custom bytecode VM + anti-tamper gate

## Mission briefing
A towed car's immobiliser module dumps a single opaque blob and a mechanic's note; the keyfob tool that shipped with it is subtly wrong and will happily show you a program that prints a decoy 'ignition' phrase. The blob is bytecode for a small machine, and it refuses to cooperate when read through a bad lens — the correct phrase is the only string that satisfies the module's own checksum.

## Objective
Repair your reading of the bytecode, execute it correctly, and recover the ignition phrase. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `ignition.vmb`
- `YARD_NOTES.txt`
- `disassemble.py`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
