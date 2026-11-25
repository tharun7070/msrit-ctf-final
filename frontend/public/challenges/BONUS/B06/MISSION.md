# B06 · Wi-Fi Named 'FBI Surveillance Van'

**Level:** Bonus · **Points:** 25 · **Category:** Cryptography  
**Location:** Los Santos Suburbs · **Focus:** Weak-passphrase WPA-style KDF + blob

## Mission briefing
Someone's home Wi-Fi is literally called 'FBI Surveillance Van', which is either a joke or the worst OPSEC in Los Santos. A handshake was captured and the passphrase is presumably worse than the SSID.

## Objective
Recover the passphrase, derive the keystream, and unwrap the captured blob. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `handshake.hc22000`
- `wordlist.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
