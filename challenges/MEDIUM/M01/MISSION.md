# M01 · Fleeca Vault Glitch

**Level:** Medium · **Points:** 100 · **Category:** Web security  
**Location:** Fleeca Bank · **Focus:** Two-stage stored injection + DB-keyed hashing + session gate

## Mission briefing
Fleeca's offline kiosk has two faces: a careful registration desk and a careless profile loader that trusts what it reads back. Registering is safe — the bug lives on a LATER visit, after a second sync step stores a derived copy of your data that is then interpolated raw. The login hash is home-grown and keyed with secrets that live only inside the database, and reaching the vault needs a valid session token on top of the injection. A honeypot admin account is waiting to waste your afternoon.

## Objective
Trip the two-stage stored-data flaw, satisfy the database-keyed hash, present a valid session, and retrieve the escrow record. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `fleeca_kiosk.py`
- `fleeca.db`
- `common_pw.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
