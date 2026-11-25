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

Go to the CTFd UI, run initial setup, enter name `FLAG THEFT AUTO`, choose **Team Mode**, set one administrator, configure start and end times in the admin panel. A LAN-only board still needs network connectivity between students and host; individual puzzle artifacts work fully offline. Keep public registration **closed** — crews are pre-enrolled by the organizers (see section F) so the same physical group cannot register multiple times.

## C. Import all 25 challenges via API (recommended)

This package uses the API instead of version-sensitive CTFd CSV imports. Run from the `FLAG_THEFT_AUTO_FINAL` project root:

```bash
python -m pip install -r organizer_private/CTFD_IMPORT/requirements.txt
python organizer_private/CTFD_IMPORT/import_ctfd.py  # dry run; zero network
```

Create an **admin access token** in CTFd: account Settings > Access Tokens (give it a short expiration). On Linux/macOS/WSL:

```bash
export CTFD_URL='https://your-ctfd.example'
export CTFD_TOKEN='paste-admin-token-here'
python organizer_private/CTFD_IMPORT/import_ctfd.py --apply
```

For trusted local host / LAN only:

```bash
export CTFD_URL='http://127.0.0.1:8000'
python organizer_private/CTFD_IMPORT/import_ctfd.py --apply --allow-http
```

PowerShell equivalent:

```powershell
$env:CTFD_URL = 'http://127.0.0.1:8000'
$env:CTFD_TOKEN = 'paste-admin-token-here'
python organizer_private/CTFD_IMPORT/import_ctfd.py --apply --allow-http
```

**Caution:** an admin token over plain HTTP can be intercepted on a shared LAN. For student networks use HTTPS even internally where practical. The `--allow-http` switch is for a trusted isolated setup only. Never commit/share `CTFD_TOKEN`.

The script first checks that the 25 names do not already exist, then creates each mission **hidden**, adds the static private flag, three hints (each with a `cost` so unlocking deducts points — $10/$20/$30 for Easy/Medium/Hard) and all attachments, and finally makes it visible. If it fails, it stops; the partially imported challenge remains hidden. Manually inspect/clean it in CTFd admin before re-running, rather than creating duplicates. It uses supported 3.x API endpoints: `POST /api/v1/challenges`, `/flags`, `/hints`, `/files`, and `PATCH /api/v1/challenges/<id>`.

### C2. Import the BONUS WAVE (10 extra missions, left hidden)

The bonus missions are a separate manifest (`manifest_bonus.json`) and are imported **hidden** — they are never published here. A scheduler flips them visible mid-event.

```bash
python organizer_private/CTFD_IMPORT/import_ctfd.py --bonus            # dry run
python organizer_private/CTFD_IMPORT/import_ctfd.py --apply --bonus --allow-http   # (or HTTPS URL)
```

Then schedule the reveal by setting the event start in `.env` (copy from `.env.example`):

```
EVENT_START=2026-11-25T10:00:00+05:30   # the moment the board goes live
BONUS_REVEAL_OFFSET_MINUTES=60          # reveal 60 minutes into the solve window
# or pin an absolute time instead: BONUS_REVEAL_AT=2026-11-25T11:00:00+05:30
```

`docker compose up -d --build` starts a `bonus-reveal` container (built from `Dockerfile.reveal`, so it needs no network at event start) that waits until `EVENT_START + offset`, then publishes the 10 hidden missions. It is idempotent and restart-safe (already-visible missions are skipped). To reveal immediately (e.g. a rehearsal), run `python organizer_private/CTFD_IMPORT/reveal_bonus.py --now` with `CTFD_URL`/`CTFD_TOKEN` set.

## D. Essential post-import checks (must be done on YOUR live server)

1. From admin console confirm **25** standard missions visible, **2,200** available points, 75 hints (each with a non-zero cost), and 58 distinct attachment uploads. If the bonus wave is preloaded, admin also shows **10** hidden bonus missions (35 total; only 25 visible/scoreable until the reveal).
2. Confirm the 10 bonus missions are `hidden` and that a non-admin team cannot see or submit them before T+60; then verify they appear after the reveal (or after `reveal_bonus.py --now`).
3. Create a separate student test team and check that downloads work and flags are *not* visible before solving.
4. Submit an intentionally wrong flag, then one known correct flag using the private answer key; verify the score increments exactly once. Delete the test team's solves or reset the test board before the event.
5. Check every mission's file names, Markdown rendering, hint unlocking (verify a hint unlock deducts points), and login on a student device over the actual event network. For a bonus mini-game mission (B01–B04), open the game card, win it, and confirm the printed key actually decodes that mission's artifact.
6. Test max simultaneous teams, clock settings, leaderboard sorting and closing behavior. Backup the CTFd database and volumes.
7. If the import itself fails, use CTFd Admin > Challenges > +, create Standard with value/category/description, then attach the private flag, files and hints manually per `organizer_private/CTFD_IMPORT/manifest.json`. **Never upload manifest.json.**

## E. Access, security and offline contingency

Do **not** host any Python challenge files as network-exposed vulnerable services. They are stand-alone downloaded programs that run locally. Hand out the participant bundle only, never the master ZIP. Keep `organizer_private` on an organizer-only drive. If the board is down, use the pre-distributed participant files and the controlled offline submission sheet, then resync once restored.

## F. Provision crew credentials (one login set per team)

Public registration is closed so a single physical crew cannot create multiple teams. Instead, each crew is pre-enrolled with its own credentials via the admin API:

```bash
python organizer_private/CTFD_IMPORT/provision_teams.py --roster roster.csv          # dry run
export CTFD_URL='https://your-ctfd.example'
export CTFD_TOKEN='paste-admin-token-here'
python organizer_private/CTFD_IMPORT/provision_teams.py --apply --roster roster.csv
```

`roster.csv` is one row per crew: `team_name,member1[,member2][,member3]`. The script creates one team plus each member's login, disables public registration (`registration_visibility=private`), and writes the private `organizer_private/team_credentials.csv`. Hand each crew only its own rows. Without a roster, `--teams N` auto-generates `N` placeholder crews for a dry run.

**Verification status for this edition:** 25 local solve tests passed, plus 10 bonus solve tests; importer dry-run, mock-API sequence and the bonus-reveal mock sequence passed. No real CTFd deployment occurred in the build environment; your LAN smoke test above is mandatory.
