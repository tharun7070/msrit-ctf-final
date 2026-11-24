# EVENT-DAY RUNBOOK · 150 MINUTES

**Roles:** Event Director (clock and public announcements), CTFd Admin (accounts, server), Head Judge (private key keeper), Help Desk (team devices), Incident Scribe (neutral timeline). Recommend at least four staff.

## Before participants arrive (T−60 to T−5)

- Confirm server reachable from student network; record LAN URL and test with non-admin account. Check CTFd start/close times and server clock (Asia/Kolkata event zone).
- Run private validation. Preload the 25 missions through API. Check 75 hints and 58 attachment uploads on actual server. Provision one credential set per crew (`provision_teams.py`) and print/distribute each crew's row-group.
- Test one real student device and one Windows+WSL Linux ELF workflow. Ensure no campus network exploitation is required.
- Print QR to CTFd base URL and rules; put participant-only ZIP on a public read-only share, bring USB backup.
- Keep master ZIP/answer key in a password-protected organizer-only location. Take a DB/volume backup before opening.
- Decide whether AI assistants are permitted; announce one policy for everyone.

## Live 150-minute timeline

| Elapsed | Stage | Director action |
|---|---|---|
| 00:00–00:15 | Opening (15 min) | GTA-inspired story, team size, scope, no live attacks, flag syntax, fair play |
| 00:15–00:25 | Login & briefing (10 min) | Crews log in with their pre-issued credentials, open an Easy sample, verify downloads; no real flag reveals |
| 00:25–02:05 | Missions live (100 min) | Make all 25 visible, start scoring; check health every 10 minutes; hints cost points on unlock |
| 02:05–02:10 | Submission grace (5 min) | No new puzzle work; allow already recovered flags; final cutoff at 02:10 |
| 02:10–02:20 | Verification (10 min) | Close scoring; export standings, check ties, address documented incidents |
| 02:20–02:30 | Results & closing (10 min) | Announce winners, prize awards, release post-event educational solutions later |

**Public clock rule:** main solve time 100 minutes; final 5 minutes are submission-only grace; official accepted submission cutoff is 02:10 (130 minutes after start). No submissions count after this. The remaining 10-minute verification is separate. Configure CTFd closing time to the correct 130-minute point or close manually with judges observing.

## At opening

Director says: “Welcome to FLAG THEFT AUTO. Your crew has 100 minutes to raid fictional digital evidence across Los Santos. Submit only flags in exact `FTA{...}` form. Hints are optional and each unlock deducts points from your score. All actions are limited to the provided offline artifacts. The board is the only official scoreboard, unless we announce backup mode.”

## Outage and fairness procedures

**Internet outage, LAN server healthy:** continue via LAN; participant local files work offline. No time compensation if all teams maintain equal access.

**CTFd inaccessible for >3 minutes:** note exact start, announce global pause, do not accept private one-off scores. Provide participant-only ZIP if needed. Restore server. Extend end time by the same documented downtime or activate controlled offline submissions for all crews, not selected teams. Make one official public announcement.

**Login issues:** help desk checks approved username/team name, password reset via CTFd admin; no sharing credentials. Assign temporary crew ID if offline backup mode. Never request passwords in public chat.

**Challenge is defective:** head judge verifies with `validate_challenges.py`, then announces a globally equal correction or removes it from scoring. Record team/mission/time, never reveal the flag publicly.

**PCAP/ELF/Pillow unavailable on some devices:** provide a supervised lab computer with Wireshark, Python and Linux/WSL. Don't relax the challenge answer for individual teams.

## At closing

Freeze accepted solves at the published cutoff; export scoreboard and solve timestamps. If offline mode is active use `organizer_private/verify_submissions.py` on the private submission CSV. Check tie-break timestamps and dispute log. Announce results only after head judge signs off. Keep secrets private until a deliberate post-event walkthrough.

## Incident log template

`HH:MM IST | Incident | Affected teams | Announcement | Resolution | Approved by`

## Immersive radio announcements (optional, spoken by the host)

**Opening:** “Los Santos control to all crews: dispatch has scattered twenty-five digital clues across the city. Every tool you need is in the evidence. Your first task is to find the signal beneath the noise.”

**At 30 minutes into solve window:** “The Street Job is nearly behind you. Fleeca and the airport are reporting unusual traffic. The Big Heist is calling.”

**At 60 minutes into solve window:** “Zancudo's terminal is active. The impound archive is leaking clues. The Final Getaway is yours to crack.”

**At 90 minutes into solve window:** “Final ten minutes of active mission time. Use hints if needed — each unlock deducts points; check your flag format before submitting.”

**At close:** “The gates are shutting. Only accepted submissions before the posted cutoff count. Head judges are verifying the final standings.”

Keep all announcements neutral; do not imply that stages are locked or that a participant must solve earlier missions first.
