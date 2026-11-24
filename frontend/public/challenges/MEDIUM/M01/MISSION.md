# M01 · Fleeca Vault Glitch

**Level:** Medium · **Points:** 100 · **Category:** Web security  
**Location:** Fleeca Bank · **Focus:** Two-stage stored injection + un-reversed alias + veiled columns + session gate

## Mission briefing
Fleeca's offline kiosk has two faces: a careful registration desk and a careless profile loader that trusts what it reads back. The bug lives on a LATER visit — after a second sync stores a derived copy of your data, written through one more transform the loader never reverses. The escrow columns come back veiled, keyed by a session you must earn first, and the obvious ledger is a trap wired to a canary that poisons your teller session and serves decoy rows. A honeypot admin is still waiting to waste your afternoon.

## Objective
Trip the multi-stage stored-data flaw through the un-reversed transform, derive the session key, unveil the columns, and avoid the canary. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `fleeca_kiosk.py`
- `fleeca.db`
- `common_pw.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
