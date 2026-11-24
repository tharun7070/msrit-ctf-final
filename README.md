# FLAG THEFT AUTO // FULL-STACK GTA VI CINEMATIC CTF PLATFORM

A production-ready, full-stack cybersecurity competition platform built for college TechFests. Combines the cinematic visual aesthetic of the GTA VI landing page reference with an integrated CTFd backend and 25 real, validated cybersecurity challenges.

```
       _____ _        _    ____   _____ _   _ _____ _____ _____     _   _   _ _____ ___  
      |  ___| |      / \  / ___| |_   _| | | | ____|  ___|_   _|   / \ | | | |_   _/ _ \ 
      | |_  | |     / _ \| |  _    | | | |_| |  _| | |_    | |    / _ \| | | | | || | | |
      |  _| | |___ / ___ \ |_| |   | | |  _  | |___|  _|   | |   / ___ \ |_| | | || |_| |
      |_|   |_____/_/   \_\____|   |_| |_| |_|_____|_|     |_|  /_/   \_\___/  |_| \___/ 
                                VICE CITY // CYBER HEIST
```

---

## Key Features

- **Cinematic Landing Page**: Built using React 19, Vite, Tailwind CSS 4, and GSAP with ScrollTrigger. Features SVG text masking, scroll-scrubbed 4K video scenes, pinned parallax transitions, and oversized typography.
- **Complete Heist Economy**: All 25 challenges pay out in fictional cash (`$`), perfectly synchronized with CTFd scores ($50 Easy, $100 Medium, $160 Hard — total available: **$2,200**).
- **Authoritative CTFd Backend**: Pre-provisioned crew credentials, login, 2–3 person team syndicates, server-side flag validation, progressive hint unlocking, and live scoreboard calculation. Public registration is **closed** — the organizer issues one credential set per crew to prevent duplicate sign-ups.
- **Zero Client-Side Secrets**: Private flags, solutions, and answers are never sent to the browser or bundled in frontend code.
- **Mission Passed Celebration**: GTA-style animated overlay with cash award pulses when CTFd confirms a correct flag.
- **Lester's Workbench**: Six built-in offline decoder tools (Base64, Hex to ASCII, ROT13, Caesar cipher, XOR decoder, text reverser).
- **Offline LAN Ready**: All fonts, images, and videos are hosted locally. Does not require public internet access during competition.

---

## Project Structure

```
FLAG_THEFT_AUTO_FINAL/
├── frontend/                 # React 19 + Vite + Tailwind 4 SPA
│   ├── src/
│   │   ├── sections/         # Cinematic landing page sections (Hero, Videos, Acts, Outro)
│   │   ├── pages/            # App routes (Dashboard, Missions, Briefing, Leaderboard, Crew, Intel)
│   │   ├── components/       # HUD elements, CountdownTimer, WantedStars, MissionPassedOverlay
│   │   ├── services/         # CTFd REST API v1 client (auth, teams, challenges, submissions)
│   │   ├── hooks/            # useAuth, useChallenges
│   │   ├── data/             # Challenge metadata & level colors (no private flags)
│   │   └── styles/           # Tailwind 4 custom theme & GTA HUD styles
│   ├── public/               # Local fonts (Long, Round), images, and MP4 videos
│   ├── package.json
│   └── vite.config.js
├── challenges/               # Participant-safe challenge files (E01–E12, M01–M08, H01–H05)
├── organizer_private/        # Organizer answer keys, solutions, and CTFd import manifest
├── scripts/
│   ├── import_challenges.py  # CTFd challenge importer wrapper
│   └── validate_challenges.py# Pre-flight audit & security integrity tester
├── tests/
│   └── test_dist_security.py # Scans production bundles for leaked secrets
├── docs/
│   ├── INSTALLATION.md       # Setup & startup instructions
│   ├── DEPLOYMENT.md         # Production server LAN guide
│   ├── EVENT_DAY.md          # 150-minute competition runbook
│   └── ARCHITECTURE.md       # Full architectural breakdown
├── docker-compose.yml        # Multi-container CTFd + Postgres + Redis + Nginx
├── nginx.conf                # Reverse proxy with rate-limiting & security headers
└── .env.example              # Sample environment configuration
```

---

## 25 Competition Challenges

| Act | ID | Mission Title | Category | Focus | Reward |
|---|---|---|---|---|---|
| **Easy** | E01 | Lester's Pager Panic | Cryptography | Dual modular filter + per-row stream permutation | $50 |
| | E02 | Vinewood Shift Change | Cryptography | Dual fingerprint gate + transposition-over-substitution | $50 |
| | E03 | Sandy Shores Hidden Stash | Linux Forensics | ext2 recovery + multi-byte keyed mask | $50 |
| | E04 | Del Perro Camera Roll | Digital Forensics | Gated bit-plane stego + geometry-keyed mask | $50 |
| | E05 | Wrong Extension, Right Exit | File Forensics | Triple-format polyglot + PBKDF2 AES + 3-table database | $50 |
| | E06 | Payphone Static | Signal Forensics | Split DTMF burst + custom keypad + keyed XOR | $50 |
| | E07 | Wanted Poster | Cryptography | Hue-keyed Vigenere over a rail fence | $50 |
| | E08 | Dead Drop Uplink | Network Forensics | Custom UDP sessions + CRC gate + keyed XOR | $50 |
| | E09 | Chop Shop Terminal | Web Security | Obfuscated client-side checker + PRNG keystream | $50 |
| | E10 | Towing Yard Ignition | Reverse Engineering | Custom bytecode VM + anti-tamper gate | $50 |
| | E11 | Ghost Relay | Network Forensics | Offline wire capture + custom relay reassembly | $50 |
| | E12 | Relay Archive | Network Forensics | Offline relay archive + dual-carrier merge + decoy replays | $50 |
| **Medium** | M01 | Fleeca Vault Glitch | Web Security | Two-stage stored injection + session gate | $100 |
| | M02 | Airport Ghost Flight | Network Forensics | IPv4 fragmentation + nested frames + nonce-keyed mask | $100 |
| | M03 | LSPD Midnight Audit | Log Forensics | Keyed chain + hidden salt + triply-nested delta | $100 |
| | M04 | Underground XOR Radio | Cryptography | Three interleaved LFSRs + partial KPA + lane transpose | $100 |
| | M05 | Debugging the Dispatch | Programming | Serialised race + three-bug stage 2 + stage-3 unwrap | $100 |
| | M06 | Nightshift Loader — Part 1 | Malware Analysis | Private packer + rotated key table + custom base | $100 |
| | M07 | Nightshift Config — Part 2 | Malware Analysis | Smeared RAM XOR key + keyed KDF/HMAC + decoy section | $100 |
| | M08 | Nightshift C2 — Part 3 | Malware Analysis | Stateful C2 protocol + HMAC-gated chained frames | $100 |
| **Hard** | H01 | Zancudo Deadbolt | Reverse Engineering | Anti-analysis traps + chained VMs + runtime-keyed vault | $160 |
| | H02 | The Recursive Freeway | Algorithms | Weighted graph isomorphism + spectral fingerprint | $160 |
| | H03 | Impound Evidence Matryoshka | Multi-stage Forensics | 7-layer chained stego + cryptographic nesting | $160 |
| | H04 | LEGAL RAGGING | Secure Code Review | Blinded RSA-CRT fault + timing oracle + freshness gate | $160 |
| | H05 | Last Ride Out | Multilayer Crypto | 4-party agreement break + HKDF + nested AES | $160 |
| **TOTAL** | | **25 MISSIONS** (12 Easy / 8 Medium / 5 Hard) | | | **$2,200** |

---

## Startup & Execution

### Option 1: Docker Compose (Production / Event Day)
```powershell
cd d:\ctf\FLAG_THEFT_AUTO_FINAL
Copy-Item .env.example .env
docker compose up -d
```
Access points:
- **CTF Web Platform**: `http://localhost`
- **CTFd Admin Panel**: `http://localhost:8000/admin`

### Option 2: Local Development
```powershell
# 1. Start CTFd backend in Docker
docker compose up db cache ctfd -d

# 2. Run the React frontend
cd d:\ctf\FLAG_THEFT_AUTO_FINAL\frontend
npm run dev
```
Access at `http://localhost:3000`.

### Challenge Importer
```powershell
$env:CTFD_TOKEN = "your_admin_token"
python scripts/import_challenges.py --apply --url http://localhost:8000 --allow-http
```

### Crew Credentials (one login set per team)
Public registration is disabled. Provision one team + member logins per crew and emit a private credentials sheet:
```powershell
$env:CTFD_TOKEN = "your_admin_token"
$env:CTFD_URL   = "http://localhost:8000"
# Dry run (no network, no file writes):
python organizer_private\CTFD_IMPORT\provision_teams.py --roster roster.csv
# Apply (creates teams/users, disables public registration, writes organizer_private\team_credentials.csv):
python organizer_private\CTFD_IMPORT\provision_teams.py --apply --roster roster.csv --allow-http
```
Hand each crew only its own row-group; the credentials CSV is organizer-private.

### Verification
```powershell
python scripts/validate_challenges.py
python tests/test_dist_security.py
```
