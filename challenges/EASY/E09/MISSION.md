# E09 · Chop Shop Terminal

**Level:** Easy · **Points:** 50 · **Category:** Web security  
**Location:** Strawberry · **Focus:** Obfuscated client-side checker + PRNG keystream

## Mission briefing
A Strawberry chop shop screens clients with a browser 'terminal' that validates an access token locally. The checker is buried under a rotating string table and a home-grown generator, and it lies in two places: a dead branch and a comment both offer 'the' key, and neither opens the door. The only truth is the arithmetic the page actually runs.

## Objective
Recover the token the checker would accept — without a browser doing the work for you. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `terminal.html`
- `chopshop.js`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
