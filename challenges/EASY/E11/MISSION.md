# E11 · Ghost Relay

**Level:** Easy · **Points:** 50 · **Category:** Network forensics  
**Location:** Paleto Bay · **Focus:** Offline wire capture + custom relay reassembly

## Mission briefing
A black-market courier relay in Paleto Bay was caught mid-drop, and the only thing recovered is a short wire capture of the burst it threw back at a passer-by who poked it. The relay never talks first, and when it did answer it did not answer politely — the parcel came back as a scatter of small datagrams leaving from several ports at once, salted with a replay nobody asked for. Listen on a single socket and you read noise; you have to work the whole conversation at the frame level to decide which fragments are the drop. Everything you need is already in the capture.

## Objective
Reassemble the parcel hiding in the capture and submit the flag. Submit exactly one recovered flag to CTFd, in the form `FTA{...}`. The braces and capitalization matter. Do not submit explanations.

## Evidence files
- `ghost_relay.pcap`

## Scope and safety
Work only on the downloaded challenge artifacts. All targets, identities and addresses are fictional. No scanning, account access, or attacks against a real network are required or allowed.

Hints are unlockable on the event platform; they are not required to solve the mission.
