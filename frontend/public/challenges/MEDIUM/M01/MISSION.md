# M01 · Fleeca Vault Glitch

**Level:** Medium · **Points:** 100 · **Category:** Web security  
**Location:** Fleeca Bank · **Focus:** Second-order SQL injection + custom hashing

## Mission briefing
Fleeca's offline kiosk has two faces: a careful registration desk and a careless profile loader that trusts what it reads back. Its login uses a home-grown password hash no cracker will recognise. To reach the vault you must trip both.

## Objective
Exploit the loader's stored-data flaw and satisfy the custom hash, then retrieve the audit record. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `fleeca_kiosk.py`
- `fleeca.db`
- `common_pw.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
