# E06 · Payphone Static

**Level:** Easy · **Points:** 50 · **Category:** Steganography  
**Location:** Little Seoul · **Focus:** Split DTMF burst + custom keypad + keyed XOR

## Mission briefing
A payphone outside a Little Seoul laundromat kept spitting out a call nobody placed. The recording is mostly handshake noise; the genuine traffic only begins after a long dead interval. The file hides more than it says — a lazy low-bit sweep hands you a smug little flag that is a lie — and what follows the gap is a two-block keypad code plus a payload sealed with a key you must first assemble from the keypad block itself.

## Objective
Recover the single courier phrase. The recording names nothing: split the burst, discard the handshake, rebuild the key, and peel the payload. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `payphone.wav`
- `EXCHANGE.txt`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
