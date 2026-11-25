# H03 · Impound Evidence Matryoshka

**Level:** Hard · **Points:** 160 · **Category:** Multi-stage forensics  
**Location:** Los Santos Police Department · **Focus:** 7-layer chained stego + cryptographic nesting

## Mission briefing
The impound lot's evidence camera, impound_camera.png, came back from the techs with an unexpected second job: it is a matryoshka. Nine shells sit stacked inside the image and its trailing sectors, each one locked by something you only recover from the shell before it, and several artefacts are placed specifically to send you home early with a convincing fake. One field note describes the whole stack as arithmetic and structure; a separate 'official quick-cut card' claims to shortcut it. Recover the true recovered_flag.

## Objective
Recover the genuine recovered_flag from impound_camera.png by peeling all nine chained shells and ignoring the planted bait. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `impound_camera.png`
- `EVIDENCE_NOTE.txt`
- `RECOVERY_INSTRUCTIONS.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
