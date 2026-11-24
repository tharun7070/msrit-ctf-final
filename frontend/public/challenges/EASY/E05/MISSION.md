# E05 · Wrong Extension, Right Exit

**Level:** Easy · **Points:** 50 · **Category:** File forensics  
**Location:** Los Santos Customs · **Focus:** Triple-format polyglot + PBKDF2 AES + 3-table database

## Mission briefing
A customs courier filed a manifest that is three files at once: a clean customs form, to another reader something else entirely, and to a third yet another thing. `file` will not save you here. Folded inside is an encrypted archive whose passphrase is not printed anywhere — it is assembled from two separate values the form holds apart, pushed through a slow KDF, with the IV carried somewhere other than the ciphertext. What comes back is a database, and the flag sits behind a join no single table can answer.

## Objective
Unwrap the polyglot, derive the key from the two separated fields, decrypt the archive, and resolve the three-way join. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `impound_dossier.pdf`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
