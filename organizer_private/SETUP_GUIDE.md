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

The script first checks that the 15 names do not already exist, then creates each mission **hidden**, adds the static private flag, three zero-cost hints and all attachments, and finally makes it visible. If it fails, it stops; the partially imported challenge remains hidden. Manually inspect/clean it in CTFd admin before re-running, rather than creating duplicates. It uses supported 3.x API endpoints: `POST /api/v1/challenges`, `/flags`, `/hints`, `/files`, and `PATCH /api/v1/challenges/<id>`.

## D. Essential post-import checks (must be done on YOUR live server)

1. From admin console confirm **15** standard missions, **1,550** available points, 45 hints, and 28 distinct attachment uploads.
2. Create a separate student test team and check that downloads work and flags are *not* visible before solving.
3. Submit an intentionally wrong flag, then one known correct flag using the private answer key; verify the score increments exactly once. Delete the test team's solves or reset the test board before the event.
4. Check every mission's file names, Markdown rendering, free hint unlocking, and login on a student device over the actual event network.
5. Test max simultaneous teams, clock settings, leaderboard sorting and closing behavior. Backup the CTFd database and volumes.
6. If the import itself fails, use CTFd Admin > Challenges > +, create Standard with value/category/description, then attach the private flag, files and hints manually per `ORGANIZER/CTFD_IMPORT/manifest.json`. **Never upload manifest.json.**

## E. Access, security and offline contingency

Do **not** host any Python challenge files as network-exposed vulnerable services. They are stand-alone downloaded programs that run locally. Hand out `FLAG_THEFT_AUTO_PARTICIPANT.zip` only, never the master ZIP. Keep `ORGANIZER` and `CHALLENGE_SOURCE` on an organizer-only drive. If the board is down, use pre-distributed participant ZIP and the controlled offline submission sheet, then resync once restored.

**Verification status for this edition:** 15 local solve tests passed; importer dry-run and mock-API sequence passed. No real CTFd deployment occurred in the build environment; your LAN smoke test above is mandatory.
