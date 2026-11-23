# E05 · Wrong Extension, Right Exit

**Level:** Easy · **Points:** 50 · **Category:** File forensics  
**Location:** Los Santos Customs · **Focus:** PDF/ZIP polyglot + AES + SQLite

## Mission briefing
A customs courier filed a manifest that is two files at once: it opens as a clean customs form and, to a different reader, as something else entirely. Folded inside is an encrypted archive — keyed by a serial the form prints in plain sight, if you can actually read the field and not just the text.

## Objective
Unwrap the polyglot, decrypt the inner archive, and query the recovered database. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `impound_dossier.pdf`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
