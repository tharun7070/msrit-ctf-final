# FLAG THEFT AUTO // FULL-STACK GTA VI CINEMATIC CTF PLATFORM

A production-ready, full-stack cybersecurity competition platform built for college TechFests. Combines the cinematic visual aesthetic of the GTA VI landing page reference with an integrated CTFd backend and 15 real, validated cybersecurity challenges.

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
- **Complete Heist Economy**: All 15 challenges pay out in fictional cash (`$`), perfectly synchronized with CTFd scores ($50 Easy, $100 Medium, $160 Hard — total available: **$1,550**).
- **Authoritative CTFd Backend**: Real user registration, login, 2–3 person team syndicates, server-side flag validation, progressive hint unlocking, and live scoreboard calculation.
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
├── challenges/               # Participant-safe challenge files (E01–E05, M01–M05, H01–H05)
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
│   ├── ARCHITECTURE.md       # Full architectural breakdown
│   └── TEST_RESULTS.md       # Automated test execution report
├── docker-compose.yml        # Multi-container CTFd + Postgres + Redis + Nginx
├── nginx.conf                # Reverse proxy with rate-limiting & security headers
└── .env.example              # Sample environment configuration
```

---

## 15 Competition Challenges

| Act | ID | Mission Title | Category | Focus | Reward |
|---|---|---|---|---|---|
| **Act I: The Street Job** | E01 | Lester's Pager Panic | Cryptography | Base64 decoding | $50 |
| | E02 | Vinewood Shift Change | Cryptography | Caesar cipher | $50 |
| | E03 | Sandy Shores Hidden Stash | Linux Forensics | Hidden files | $50 |
| | E04 | Del Perro Camera Roll | Digital Forensics | PNG metadata | $50 |
| | E05 | Wrong Extension, Right Exit | File Forensics | File signatures | $50 |
| **Act II: The Big Heist** | M01 | Fleeca Vault Glitch | Web Security | SQL injection simulation | $100 |
| | M02 | Airport Ghost Flight | Network Forensics | HTTP / PCAP | $100 |
| | M03 | LSPD Midnight Audit | Log Forensics | Event correlation | $100 |
| | M04 | Underground XOR Radio | Cryptography | Repeating-key XOR | $100 |
| | M05 | Debugging the Dispatch | Programming | Python debugging | $100 |
| **Act III: The Final Getaway** | H01 | Zancudo Deadbolt | Reverse Engineering | ELF binary | $160 |
| | H02 | The Recursive Freeway | Algorithms | Memoized DAG recursion | $160 |
| | H03 | Impound Evidence Matryoshka | Multi-stage Forensics | Polyglot archives | $160 |
| | H04 | Fleeca Trust Fall | Secure Code Review | Unsigned token logic | $160 |
| | H05 | Last Ride Out | Multilayer Crypto | Route-key derivation | $160 |
| **TOTAL** | | **15 MISSIONS** | | | **$1,550** |

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

### Verification
```powershell
python scripts/validate_challenges.py
python tests/test_dist_security.py
```
