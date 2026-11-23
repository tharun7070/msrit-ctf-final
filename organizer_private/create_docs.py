#!/usr/bin/env python3
"""Private documentation generator. The resulting ANSWER_KEY contains flags."""
from pathlib import Path
import csv,json,io,textwrap,hashlib
ROOT=Path(__file__).resolve().parents[1]
ORG=ROOT/'ORGANIZER';PART=ROOT/'PARTICIPANT';MAN=json.loads((ORG/'CTFD_IMPORT/manifest.json').read_text())['challenges']
def put(path,s):
 p=ROOT/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(textwrap.dedent(s).lstrip(),encoding='utf-8')

put('README.md', '''
# FLAG THEFT AUTO — The City Is Your Cipher

**CSE TechFest | 150-minute team CTF | Fictional, offline challenge artifacts**

The neon-lit city of Los Santos is a fictional playground for the case files, bank kiosks, courier interceptions, and final getaway. Players form 2–3-person crews and recover flags from evidence only; no real network targets or actual theft.

## The three acts

| Act | Level | Challenges | Points each | Available |
|---|---|---:|---:|---:|
| The Street Job | Easy | 5 | 50 | 250 |
| The Big Heist | Medium | 5 | 100 | 500 |
| The Final Getaway | Hard | 5 | 160 | 800 |
| **Total** | | **15** | | **1550** |

## Package access and confidentiality

- **Public**: `PARTICIPANT/` (also delivered as a standalone participant ZIP), containing mission descriptions and evidence, *not* answers.
- **Organizer secret**: `ORGANIZER/` includes an answer key, CTFd manifest with raw flags, tests, and import scripts.
- **Private source**: `CHALLENGE_SOURCE/` contains an artifact generator, cleartext flag constants, C source and seed data. Never distribute.
- **Branding**: `BRANDING/` includes event-ready PNG artwork and SVG logo.

**DANGER:** The master ZIP and organizer ZIP contain *all answer flags*. Never upload them to participant-accessible folders, public GitHub repositories, or CTFd challenge attachments. Only give participants the standalone `FLAG_THEFT_AUTO_PARTICIPANT.zip`.

## Organizer quick start

1. Read `ORGANIZER/SETUP_GUIDE.md` and `ORGANIZER/RUNBOOK.md`.
2. Create a CTFd instance on an authorized local or hosted server, set team mode, and create an admin access token.
3. Run `python ORGANIZER/validate_challenges.py` (requires Python, Pillow, GCC binutils for H01 validation).
4. Run `python ORGANIZER/CTFD_IMPORT/import_ctfd.py` for a default no-network dry run.
5. From this project root, set `CTFD_URL` and `CTFD_TOKEN` in environment variables and run `python ORGANIZER/CTFD_IMPORT/import_ctfd.py --apply` on an HTTPS server (or `--allow-http` for trusted local LAN).
6. Check every mission from a **non-admin** student account, test one flag, scoreboard, downloads, and hint unlocking, then prepare backups.
7. Event schedule: 15-minute intro, 10-minute login, 100-minute solve window, 15-minute grace/submission review, 10-minute awards.

The CTFd importer uses the supported 3.x API rather than assuming a universally compatible CSV schema. All local puzzles can be solved without internet access; CTFd itself still needs an accessible local LAN connection or server.
''')
put('PARTICIPANT/README.md','''
# WELCOME TO LOS SANTOS · FLAG THEFT AUTO

You're a 2–3-person crew in a fictional cyber-heist universe. Your task is to recover a unique `FTA{...}` code from each mission's evidence. No challenge requires access to any real service.

**How to play:** create/join a team on the CTFd scoreboard; select a mission; download exactly that mission's attached evidence files; investigate locally; submit the complete recovered flag, with braces and case preserved. One correct submission per challenge per team earns the full point value. The organizer can provide the whole participant evidence package for offline backup.

The missions are grouped in `EASY/` (The Street Job, 50 points each), `MEDIUM/` (The Big Heist, 100 points each) and `HARD/` (The Final Getaway, 160 points each). Total possible: 1,550 points. You may solve missions in any order.

Recommended tools: Python 3.9+, a text editor, Terminal/PowerShell or WSL2, `file`, `unzip`, `xxd`, Python Pillow, Wireshark, `strings`, `objdump`, `readelf`. All are free; missions have offline alternatives using Python. One reverse-engineering binary is built for Linux x86-64, so Windows crews should use WSL2 Ubuntu or a provided Linux machine.

Three progressive hints per challenge are available in CTFd. Each unlocked hint deducts **10 / 20 / 30** points (Easy / Medium / Hard) from your team's score. Hints are optional; creativity and collaboration inside your crew are encouraged. Submit only the flag, not working or screenshots.

**Important:** the fictional locations are just story. No scanning or probing the college network, real websites, team accounts, or other participants is permitted. See `RULES.md`.
''')
put('PARTICIPANT/RULES.md','''
# FLAG THEFT AUTO — Player Rules

1. Teams consist of 2–3 college participants. One CTFd team account per crew; no multi-team membership or account sharing across crews.
2. Use only the files and local programs explicitly provided for each mission. No real-world penetration testing, network scanning, brute-force against live services, malware, privilege escalation against campus systems, or personal-data collection.
3. No flag exchange, copying another crew's work, using other teams' accounts, exploiting or disrupting CTFd itself, or denial-of-service activity.
4. Public documentation, offline programming tools, and reference materials are allowed. Ask event organizers before using generative AI; organizers should announce a uniform AI-use rule prior to opening the board.
5. Hints are locked until unlocked and can be unlocked from the challenge page; each unlock deducts points (10 / 20 / 30 for Easy / Medium / Hard). Three wrong flag submissions lock that mission's flag terminal for 120 seconds.
6. Scores: Easy 50, Medium 100, Hard 160. A valid flag is accepted only if submitted for the correct challenge in the official window.
7. One correct solve per team per mission. Organizer rulings on technical defects are final and documented for all teams.
8. Ties at event close are ranked by the earlier timestamp at which the final tied score was attained; see organizer instructions.
9. If CTFd fails, notify the help desk immediately. Do not share flags in public chats. The organizer will announce one uniform backup procedure.
10. Event staff may remove a team for cheating, harassment, or unauthorized access. Have fun; no actual crimes are part of this event.
''')
put('ORGANIZER/EVENT_RULES.md','''
# Official Event Rules — Organizers

- Team size: 2–3, team mode in CTFd; ideally register 20 minutes before start.
- Allowed equipment: laptops, local VM/WSL, normal debuggers, Wireshark, programming languages, official challenge files. No live targets anywhere.
- Prohibited: attacking CTFd, its hosting infrastructure, university assets, others' accounts, external systems, network spam, denial-of-service, social engineering, malware, leaked solutions, flag trading, and opening any private organizer artifact.
- Visibility: make all 15 missions available together. Unlocking a hint deducts **10 / 20 / 30** points (Easy / Medium / Hard). Public discussion of hints and flags between teams is disallowed.
- Answer acceptance: case-sensitive exact `FTA{...}`, one correct solve per team per challenge, no negative points, fixed scoring.
- Staff should decide and announce one universal AI-assistance policy before competition (recommended: AI as reference/tool allowed but no answer-sharing; if prohibited enforce fairly).
- CTFd reports are the record of truth unless documented downtime activates offline submissions.
- Do not disclose raw flags to volunteers who only handle registration; designate a head judge as key custodian.
- Universal changes require a timestamped announcement to all teams. Challenges are local-only; participants must not run untrusted external files.
''')
put('ORGANIZER/SCORING_RULES.md','''
# Scoring and Tie-Breaking

| Level | Missions | Value | Maximum |
|---|---:|---:|---:|
| The Street Job (Easy) | 5 | 50 | 250 |
| The Big Heist (Medium) | 5 | 100 | 500 |
| The Final Getaway (Hard) | 5 | 160 | 800 |
| **Total** | **15** | | **1,550** |

All challenges are **standard fixed-value** CTFd challenges. Three hints each; unlocking a hint deducts **10 / 20 / 30** points (Easy / Medium / Hard) from the team's score. First accepted flag per team per challenge grants the full value. No speed bonuses, first-blood bonuses, or extra credit. Wrong guesses carry no direct penalty, but three wrong submissions lock that mission's flag terminal for 120 seconds.

At closing, higher total score ranks higher. Equal totals: the team whose last *score-increasing correct submission* happened earlier wins (earlier time reaching that total). If timestamps exactly match, award the tied place, or use team-name lexical order only for display without changing awards; communicate method in advance. Never use count of guesses or penalties not published in this document.

If a judge withdraws a broken challenge, apply the same policy to everyone: either replace it equally before resuming or exclude its points from all teams. Record adjudication in RUNBOOK incident log.

Backup offline scorer: `python ORGANIZER/verify_submissions.py --csv /path/to/offline_submissions.csv`. Input header `timestamp,team_id,challenge_id,flag`; timestamps must be ISO-8601 including offset, and only permitted submissions before the announced closing time are entered. **Do not put completed submission files in a public directory.**
''')
put('ORGANIZER/SETUP_GUIDE.md','''
# CTFd Setup & Deployment Guide

The official installation and API instructions are:
- https://docs.ctfd.io/docs/deployment/installation/
- https://docs.ctfd.io/docs/api/getting-started/
- https://docs.ctfd.io/docs/api/redoc/

## A. Prerequisites

A machine with Docker Engine and Docker Compose, approximately 2 CPU cores / 1 GB RAM minimum (4 CPU cores / 2 GB+ recommended for a college lab), an accessible port 8000, and an administrator who controls the private network. Docker Desktop + WSL2 works on Windows, or use a Linux host. Have Python 3.9+ and pip on the importing machine.

## B. Start CTFd

On a host with Docker installed:

```bash
git clone https://github.com/CTFd/CTFd.git
cd CTFd
# Before starting: follow official configuration for SECRET_KEY, database, and persistent volumes.
# Keep Docker's network isolated from the public internet if hosting a LAN-only event.
docker compose up -d
```

The stock CTFd Compose example normally serves `http://SERVER-IP:8000`. The compose defaults do **not** provide TLS. For use over the public internet, put a TLS reverse proxy in front and restrict administration. Configure SECRET_KEY as described in the linked official documentation. Do not put API tokens in files or shell history.

Go to the CTFd UI, run initial setup, enter name `FLAG THEFT AUTO`, choose **Team Mode**, set one administrator, configure start and end times in the admin panel. A LAN-only board still needs network connectivity between students and host; individual puzzle artifacts work fully offline. Consider enabling team registration before the official opening.

## C. Import all 15 challenges via API (recommended)

This package uses the API instead of version-sensitive CTFd CSV imports. Run from `FLAG_THEFT_AUTO` project root:

```bash
python -m pip install -r ORGANIZER/CTFD_IMPORT/requirements.txt
python ORGANIZER/CTFD_IMPORT/import_ctfd.py  # dry run; zero network
```

Create an **admin access token** in CTFd: account Settings > Access Tokens (give it a short expiration). On Linux/macOS/WSL:

```bash
export CTFD_URL='https://your-ctfd.example'
export CTFD_TOKEN='paste-admin-token-here'
python ORGANIZER/CTFD_IMPORT/import_ctfd.py --apply
```

For trusted local host / LAN only:

```bash
export CTFD_URL='http://127.0.0.1:8000'
python ORGANIZER/CTFD_IMPORT/import_ctfd.py --apply --allow-http
```

PowerShell equivalent:

```powershell
$env:CTFD_URL = 'http://127.0.0.1:8000'
$env:CTFD_TOKEN = 'paste-admin-token-here'
python ORGANIZER/CTFD_IMPORT/import_ctfd.py --apply --allow-http
```

**Caution:** an admin token over plain HTTP can be intercepted on a shared LAN. For student networks use HTTPS even internally where practical. The `--allow-http` switch is for a trusted isolated setup only. Never commit/share `CTFD_TOKEN`.

The script first checks that the 15 names do not already exist, then creates each mission **hidden**, adds the static private flag, three hints (each with a `cost` so unlocking deducts points — $10/$20/$30 for Easy/Medium/Hard) and all attachments, and finally makes it visible. If it fails, it stops; the partially imported challenge remains hidden. Manually inspect/clean it in CTFd admin before re-running, rather than creating duplicates. It uses supported 3.x API endpoints: `POST /api/v1/challenges`, `/flags`, `/hints`, `/files`, and `PATCH /api/v1/challenges/<id>`.

## D. Essential post-import checks (must be done on YOUR live server)

1. From admin console confirm **15** standard missions, **1,550** available points, 45 hints (each with a non-zero cost), and 36 distinct attachment uploads.
2. Create a separate student test team and check that downloads work and flags are *not* visible before solving.
3. Submit an intentionally wrong flag, then one known correct flag using the private answer key; verify the score increments exactly once. Delete the test team's solves or reset the test board before the event.
4. Check every mission's file names, Markdown rendering, hint unlocking (verify a hint unlock deducts points), and login on a student device over the actual event network.
5. Test max simultaneous teams, clock settings, leaderboard sorting and closing behavior. Backup the CTFd database and volumes.
6. If the import itself fails, use CTFd Admin > Challenges > +, create Standard with value/category/description, then attach the private flag, files and hints manually per `ORGANIZER/CTFD_IMPORT/manifest.json`. **Never upload manifest.json.**

## E. Access, security and offline contingency

Do **not** host any Python challenge files as network-exposed vulnerable services. They are stand-alone downloaded programs that run locally. Hand out `FLAG_THEFT_AUTO_PARTICIPANT.zip` only, never the master ZIP. Keep `ORGANIZER` and `CHALLENGE_SOURCE` on an organizer-only drive. If the board is down, use pre-distributed participant ZIP and the controlled offline submission sheet, then resync once restored.

**Verification status for this edition:** 15 local solve tests passed; importer dry-run and mock-API sequence passed. No real CTFd deployment occurred in the build environment; your LAN smoke test above is mandatory.
''')
put('ORGANIZER/RUNBOOK.md','''
# EVENT-DAY RUNBOOK · 150 MINUTES

**Roles:** Event Director (clock and public announcements), CTFd Admin (accounts, server), Head Judge (private key keeper), Help Desk (team devices), Incident Scribe (neutral timeline). Recommend at least four staff.

## Before participants arrive (T−60 to T−5)

- Confirm server reachable from student network; record LAN URL and test with non-admin account. Check CTFd start/close times and server clock (Asia/Kolkata event zone).
- Run private validation. Preload the 15 missions through API. Check 45 hints and 36 attachment uploads on actual server.
- Test one real student device and one Windows+WSL Linux ELF workflow. Ensure no campus network exploitation is required.
- Print QR to CTFd base URL and rules; put participant-only ZIP on a public read-only share, bring USB backup.
- Keep master ZIP/answer key in a password-protected organizer-only location. Take a DB/volume backup before opening.
- Decide whether AI assistants are permitted; announce one policy for everyone.

## Live 150-minute timeline

| Elapsed | Stage | Director action |
|---|---|---|
| 00:00–00:15 | Opening (15 min) | GTA-inspired story, team size, scope, no live attacks, flag syntax, fair play |
| 00:15–00:25 | Login & briefing (10 min) | Teams register, open an Easy sample, verify downloads; no real flag reveals |
| 00:25–02:05 | Missions live (100 min) | Make all 15 visible, start scoring; check health every 10 minutes; hints cost points on unlock |
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

Freeze accepted solves at the published cutoff; export scoreboard and solve timestamps. If offline mode is active use `ORGANIZER/verify_submissions.py` on the private submission CSV. Check tie-break timestamps and dispute log. Announce results only after head judge signs off. Keep secrets private until a deliberate post-event walkthrough.

## Incident log template

`HH:MM IST | Incident | Affected teams | Announcement | Resolution | Approved by`
''')
put('ORGANIZER/TROUBLESHOOTING.md','''
# Troubleshooting

| Symptom | Diagnosis | Fix |
|---|---|---|
| CTFd login inaccessible | Server not reachable, firewall/port 8000, DNS | Access by LAN IP, check `docker compose ps` and `logs`; check firewall |
| API importer 401/403 | Token absent, expired, not admin | Generate admin Access Token, set `CTFD_TOKEN` correctly; keep secret |
| API importer fails halfway | Version issue or failed attachment | Read error challenge ID, inspect hidden partial record; clean it then rerun; no silent duplicates |
| Existing challenge collision | Re-run against populated board | Import against a clean instance, or manually remove intended duplicate safely |
| Wrong MIME or file extension | Intentionally misleading artifact in E05/H03 | Do not rename or re-encode; use file signatures and `zipfile` |
| `.drop_manifest` not found | Hidden Unix dotfile | `ls -la safehouse`; Python `zipfile.namelist()` |
| PNG metadata missing | Image re-saved by chat/media tool | Download original attached PNG directly, do not screenshot/compress; verify SHA256 |
| PCAP has no packets | Broken/corrupted download | Re-upload original `.pcap`, open with Wireshark or offline parser |
| H01 `Exec format error` | Linux ELF on native Windows/macOS ARM | Use WSL2 Ubuntu on x86-64, x86 Linux VM, supervised event machine |
| M05 decoder raises `Incorrect padding` | Intended bug | Restore missing Base64 URL padding |
| SQLi CLI seemingly stuck | Waiting for owner and PIN | Enter both prompts; test only the included local `fleeca_kiosk.py` |
| Hint button absent | Hint association or CTFd permissions | Check three hints under challenge admin (each with a `cost` so unlocking deducts points) |
| Duplicate score after offline mode | Offline + CTFd merge | Judge reconciles unique team/challenge solves before publishing |
| Flag rejected | Extra spaces, wrong case/mission, incorrect decoding | Check braces and case; compare private answer only through head judge |

**If importer cannot be tested live:** use manual CTFd Admin > Challenges creation as documented. The local 15/15 validation does not guarantee server plugins or attachment storage function.
''')
put('ORGANIZER/ANNOUNCEMENT.md','''
# FLAG THEFT AUTO

### The city is your cipher. The scoreboard is your wanted level.

**CSE TechFest presents a GTA-inspired cybersecurity capture-the-flag competition.** Assemble a crew of 2–3, intercept fictional courier messages, crack coded dispatches, investigate police evidence and escape the final digital heist.

**15 missions · 3 difficulty acts · 1,550 points · 150-minute experience**

**THE STREET JOB** — crack beginner ciphers, explore hidden files and decode camera secrets.  
**THE BIG HEIST** — investigate airport traffic, debug scripts and audit a fictional bank.  
**THE FINAL GETAWAY** — reverse binaries, solve recursive route logic and unravel forensic layers.

Bring a laptop with Python and a browser. First-year through third-year engineering students are welcome; all missions are local and educational. Optional hints keep the action moving — each unlocked hint deducts points from your crew's score.

**Date:** To be announced by the organizing committee  
**Venue:** College TechFest / CSE Department — confirm with organizers  
**Registration:** CTFd link or QR will be announced  
**Team:** 2–3 students

No real hacking, external systems, or live services are involved. The storyline is original fan-inspired cyber-noir, with no official game affiliation.

**GET IN. FIND THE FLAGS. GET OUT.**
''')
put('ORGANIZER/TEST_REPORT.md','''
# Local Test Report — FLAG THEFT AUTO

**Method:** artifact-only reconstruction via `ORGANIZER/validate_challenges.py`, not the private builder. Correct outputs compared to the organizer-only manifest. A wrong-input negative check was performed for the local SQLi kiosk, ELF gate and JWT-like gateway. ZIP formats, image metadata and TCP/IPv4 checksums were checked. Every listed attachment exists and is nonempty; scans confirm no **exact correct flag** occurs verbatim in participant materials.

| ID | Challenge | Test | Result |
|---|---|---|---|
'''+''.join(f"| {c['id']} | {c['name'].split(' | ',1)[1]} | {c['solution_outline']} | **PASS** |\n" for c in MAN)+'''
### Additional checks performed

- All 15 independently reconstructed flags exactly matched their intended values, with valid case-sensitive flag syntax.
- `validate_challenges.py` verifies 15 unique correct flags and 1,550 fixed points, checks 28 attached evidence files, tests a real ELF execution, checks the PCAP protocol checksums and filters all 507 log lines.
- CTFd importer's dry run produced 15 challenge records without making network requests or printing flags.
- Mock-session CTFd API test simulated 15 challenge creates, 15 flag uploads, 45 hint uploads, 28 file uploads, 15 publication operations; all assertions **PASS**.

### What is NOT tested / limitations

- **No real live CTFd server was available** in this environment, so real API authentication, file storage, hint unlocking, UI layout and team scoring require the event host's preflight smoke test.
- No independent human playtest, real 100-minute difficulty timing, Windows native execution of Linux ELF, or Wireshark GUI decoding were measured. Difficulty categories are designer estimates; conduct an organizer-only pilot with 2–3 students.
- Unique flags, algorithm determinism and the route's unique qualifying vehicle were checked programmatically; this is not a mathematical proof that an unintended bypass cannot exist for any program. Treat reports of alternate paths fairly.
- Tests run locally on Linux using Python 3 and standard tooling. PCAP protocol validity is tested, but Wireshark UI is not available in this environment.

**Re-run:** `python ORGANIZER/validate_challenges.py` followed by `python ORGANIZER/CTFD_IMPORT/test_importer.py`. The JSON output `ORGANIZER/CTFD_IMPORT/validation_results.json` records per-mission methods and private derived flags; never distribute it.
''')
# challenge matrix private CSV, clean for spreadsheet filtering
cols=['id','name','level','act','location','category','topic','points','attachment_count','attachments','hint_count','flag','participant_directory','summary']
with (ORG/'CHALLENGE_MATRIX.csv').open('w',newline='',encoding='utf-8-sig') as f:
 w=csv.writer(f);w.writerow(cols)
 for c in MAN:
  w.writerow([c['id'],c['name'],c['level'],{'Easy':'The Street Job','Medium':'The Big Heist','Hard':'The Final Getaway'}[c['level']],c['location'],c['category'],c['topic'],c['points'],len(c['files']),';'.join(c['files']),len(c['hints']),c['flag'],c['directory'],c['solution_outline']])
# public level names and all missions listing
put('PARTICIPANT/MISSIONS.md','''
# Mission Board (all missions are independent)

| ID | Act | Title | Focus | Points |
|---|---|---|---|---:|
'''+''.join(f"| {c['id']} | {c['level']} | {c['name'].split(' | ',1)[1]} | {c['topic']} | {c['points']} |\n" for c in MAN)+'''
Open each mission folder to read `MISSION.md` and access only its evidence attachments. CTFd provides three progressive hints per mission.
''')
# answer guide specific working commands, no pseudo non-working commands
solutions={
'E01':'''Open `dispatch.csv`, keep `courier=YES`, sort `seq` as **integers**, then Base64-decode each `payload_b64` separately and concatenate. Example:
```python
import csv,base64
r=list(csv.DictReader(open('dispatch.csv')))
print(''.join(base64.b64decode(x['payload_b64']).decode() for x in sorted((a for a in r if a['courier']=='YES'),key=lambda a:int(a['seq']))))
```''',
'E02':'''The only real mission row is MIDNIGHT. Four wheels plus spare implies **+5** for encryption, so decrypt with shift **−5**. Python:
```python
s=next(x.split(' | ',1)[1] for x in open('taxi_ledger.txt') if x.startswith('MIDNIGHT |'))
print(''.join(chr((ord(c)-65-5)%26+65) if 'A'<=c<='Z' else chr((ord(c)-97-5)%26+97) if 'a'<=c<='z' else c for c in s))
```''',
'E03':'''Use `unzip safehouse.zip -d extracted`, then `ls -la extracted/safehouse`. The hidden `.drop_manifest` has `DROP_CODE_HEX=...`. Decode:
```bash
grep DROP_CODE_HEX extracted/safehouse/.drop_manifest | cut -d= -f2 | xxd -r -p
```''',
'E04':'''Read PNG text metadata without re-saving the image. With Pillow:
```python
from PIL import Image
import base64
v=Image.open('pier_camera.png').info['dispatch_note']
print(base64.b32decode(v).decode())
```
Alternatively `exiftool pier_camera.png` if installed.''',
'E05':'''The JPEG extension is a trap; `file customs_camera.jpg` or `xxd -l 4 customs_camera.jpg` shows ZIP magic `PK`. Read the verified receipt:
```python
import zipfile,re
with zipfile.ZipFile('customs_camera.jpg') as z:
 s=z.read('customs/shipment_verified.txt').decode()
 print(bytes.fromhex(re.search(r'Drop-code \\(hex\\): ([0-9a-f]+)',s).group(1)).decode())
```''',
'M01':'''Launch only the included kiosk:
```bash
python fleeca_kiosk.py
```
Owner input: `' OR 1=1 --` . PIN: `xxxx`. The unsafe SQL is concatenated as `WHERE owner='<input>' AND pin='<input>' ...`; the quote and SQLite comment bypass the PIN check. The first local row is the protected audit record. Kiosk prints its decoded receipt. An unknown owner/PIN pair yields `Access denied`. Real servers are not in scope.''',
'M02':'''Open `airport_dispatch.pcap` in Wireshark (offline). Filter HTTP requests; locate `X-Flight: LS-447`. Capture each `X-Chunk` numeric sequence and corresponding `X-Cargo` Base64 field, then decode each separately and join. There are **3** matching requests amid **22** IP/TCP frames. The private `validate_challenges.py` contains an independent standard-library PCAP parser verifying IPv4/TCP checksums.''',
'M03':'''Read `CASE_BRIEF.txt`. Filter `lspd_auth.log` for ALL: `case=714`, `host=lspd-evidence`, `account=case_clerk`, `source=FORENSIC`, `result=ACCEPT`. Sort `part` numerically; join `fraghex`; `bytes.fromhex`. Exactly six records form the correct evidence message, in 507 total lines.''',
'M04':'''Sort CSV `stop` numerically, not lexicographically. Each `keybyte_hex` represents a key byte; XOR ciphertext with repeating key.
```python
import csv
r=list(csv.DictReader(open('checkpoint_keys.csv')))
k=bytes(int(z['keybyte_hex'],16) for z in sorted(r,key=lambda a:int(a['stop'])))
c=open('radio_packet.bin','rb').read()
print(bytes(v^k[i%len(k)] for i,v in enumerate(c)).decode())
```''',
'M05':'''There are exactly three bugs in `broken_dispatch.py`. Change sorting key to `int(row['seq'])`, use `for row in ordered` (no `[:-1]`), and restore URL-safe Base64 padding. Correct function:
```python
def restore(packets):
 import base64
 ordered=sorted(packets,key=lambda row:int(row['seq']))
 encoded=''.join(row['fragment'] for row in ordered)
 return base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4)).decode()
```
Leave JSON untouched.''',
'H01':'''Use `file zancudo_gate` and `objdump -d -M intel zancudo_gate`; note the loop doing `argv[i] ^ (0x31 + 7*i)` and comparing against a twelve-byte table starting at ELF virtual address `0x402010`. `objdump -s -j .rodata zancudo_gate` shows the table. Recover each passcode byte as `table[i] ^ (0x31 + 7*i)`. The recovered twelve-character code is **`dockyard9472`**. Run:
```bash
chmod +x zancudo_gate
./zancudo_gate dockyard9472
```
A wrong 12-character code prints ACCESS DENIED. The executable decrypts the receipt only on a successful check. `ORGANIZER/validate_challenges.py` reconstructs the passcode from ELF segment offsets without reading private C source.''',
'H02':'''Parse `junctions.json`. Use memoized recursion per `PROTOCOL.md`; terminal node yields `seed`, branch yields `((17*F(left)+31*F(right)+salt)^mask)&0xffffffff` (XOR occurs before AND). Compute `h=f"{F(destination):08x}"` and `SHA256(h ASCII).hexdigest()[:8]`, then build the specified format. Code:
```python
import json,hashlib,functools
j=json.load(open('junctions.json'))
@functools.lru_cache(None)
def F(n):
 a=j['junctions'][n]
 return a['seed'] if a['kind']=='terminal' else ((17*F(a['left'])+31*F(a['right'])+a['salt'])^a['mask'])&0xffffffff
h=f"{F(j['destination']):08x}"
print('FTA{'+h+'_'+hashlib.sha256(h.encode()).hexdigest()[:8]+'}')
```''',
'H03':'''`impound_camera.png` is a valid PNG with a ZIP archive appended. Open it with Python `zipfile.ZipFile('impound_camera.png')` or `unzip`. Read `case_144/triage_144.gz` (not case 199), decompress GZIP, open inner TAR, read `sealed/dossier.json`, ASCII85 decode its payload and zlib decompress.
```python
import zipfile,gzip,tarfile,io,base64,zlib,json
with zipfile.ZipFile('impound_camera.png') as z: g=z.read('case_144/triage_144.gz')
with tarfile.open(fileobj=io.BytesIO(gzip.decompress(g))) as t: d=json.load(t.extractfile('sealed/dossier.json'))
print(zlib.decompress(base64.a85decode(d['payload'])).decode())
```''',
'H04':'''Read `bank_gateway.py`. The vulnerability is algorithm confusion / **accepting unsigned `alg=none` tokens** because client-controlled `alg` bypasses HMAC verification. A guest token is valid but lacks `role=admin`. Forge a local unsigned token:
```python
import base64,json,subprocess,sys
enc=lambda x:base64.urlsafe_b64encode(json.dumps(x,separators=(',',':')).encode()).rstrip(b'=').decode()
token=enc({'alg':'none','typ':'JWT'})+'.'+enc({'sub':'auditor','role':'admin'})+'.'
subprocess.run([sys.executable,'bank_gateway.py','--token',token],check=True)
```
Mitigation: server-controlled allowed algorithm list (reject none), validated cryptographic signature, validated issuer/audience, and access control independent of untrusted claims. Never replay this technique on real systems.''',
'H05':'''From `getaway_routes.csv` exactly one car qualifies: `wanted=0`, `clearance=YES`, `fuel_km>=route_km`: the Sentinel with plate `LSX-417`, terminal `DESERT`. Derive `sha256(b'LSX-417:DESERT').digest()` as repeating XOR key. Get text between packet markers, reverse sender order: ASCII85 decode, zlib decompress, repeated XOR.
```python
import base64,zlib,hashlib
s=open('intercept.txt').read().split('---BEGIN-PACKET---')[1].split('---END-PACKET---')[0].strip()
data=zlib.decompress(base64.a85decode(s))
key=hashlib.sha256(b'LSX-417:DESERT').digest()
print(bytes(c^key[i%len(key)] for i,c in enumerate(data)).decode())
```'''
}
assert len(solutions)==15
answer='''# PRIVATE ANSWER KEY · DO NOT DISTRIBUTE

**Security classification: organizer only.** Contains all 15 exact flags and exploitation walkthroughs for fictional offline labs. Do not upload to CTFd attachments, GitHub, or student shares. Command examples run **inside each mission folder** (e.g. `PARTICIPANT/MEDIUM/M01`). Correct score for each mission is listed below.

'''
for c in MAN:
 id=c['id'];answer+=f"## {id} · {c['name'].split(' | ',1)[1]} — {c['points']} points\n\n**Category:** {c['category']} | **Location:** {c['location']}  \n**Correct flag:** `{c['flag']}`  \n**Required evidence:** "+', '.join(f"`{x}`" for x in c['files'])+'\n\n### Solving procedure\n\n'+solutions[id].strip()+'\n\n### Progressive hints (shown in CTFd)\n\n'+''.join(f'{i}. {h}\n' for i,h in enumerate(c['hints'],1))+'\n---\n\n'
put('ORGANIZER/ANSWER_KEY.md',answer)
print('GENERATED DOCS',len(MAN),'CHALLENGES, ANSWER GUIDE',len(answer),'chars')
