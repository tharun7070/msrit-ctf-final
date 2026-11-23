# FLAG THEFT AUTO — System Architecture

## Overview

FLAG THEFT AUTO is a full-stack, cinematic cybersecurity CTF platform inspired by Grand Theft Auto VI aesthetics and built for college TechFest competitions. It combines high-end GSAP scroll-driven animations with production-grade CTFd scoring and challenge dispatch.

```
┌─────────────────────────────────────────────────────────────────┐
│                      PARTICIPANT BROWSER                        │
│                                                                 │
│   Landing Page (GSAP Scroller, Mask Video, Act Showcases)       │
│   Auth / Registration (GTA Case Dossier UI)                     │
│   Crew Hub (2–3 Participant Syndicate Roster)                   │
│   Mission Board (15 Contracts across 3 Acts: Easy, Med, Hard)   │
│   Mission Briefing (Evidence Downloads & Live Flag Transmit)    │
│   Live Leaderboard ("Los Santos Most Wanted" 10s Live Sync)    │
│   Lester's Workbench (Client-Side Field Decryption Toolkit)    │
└────────────────┬───────────────────────────────┬────────────────┘
                 │ (Frontend Routes)             │ (API / Flag Submissions)
                 ▼                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                     NGINX REVERSE PROXY                         │
│                    (Port 80 / Single Origin)                    │
│                                                                 │
│  - Serves compiled React SPA assets with long-term cache        │
│  - Reverse-proxies /api/ to CTFd backend on port 8000           │
│  - Enforces rate limiting on /api/v1/challenges/attempt         │
│  - Transparent cookie / session forwarding                      │
│  - Blocks access to organizer_private / answer keys             │
└────────────────────────────────┬────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                        CTFD BACKEND                             │
│                  (Port 8000 / Authoritative)                    │
│                                                                 │
│  - Session management & password hashing (bcrypt)               │
│  - Dynamic flag validation & scoring arithmetic                │
│  - Team membership enforcement (3 members maximum)              │
│  - Challenge file downloads (/files/...)                        │
│  - Live scoreboard calculation & tie-breaking                   │
└─────────────────┬──────────────────────────────┬────────────────┘
                  │                              │
                  ▼                              ▼
    ┌───────────────────────────┐  ┌───────────────────────────┐
    │     POSTGRESQL 15 DB      │  │       REDIS 7 CACHE       │
    │  - Challenges & Flags     │  │  - Session cache          │
    │  - Teams & Users          │  │  - Scoreboard rate limits │
    │  - Solves & Submissions   │  └───────────────────────────┘
    └───────────────────────────┘
```

## Security Model

1. **Zero Client-Side Flags**: No flags, regexes, or verification logic are ever sent to the browser.
2. **Server-Side Validation**: All flag attempts go through CTFd's `/api/v1/challenges/attempt` endpoint.
3. **No LocalStorage Scoring**: Scores and completed status come strictly from authenticated CTFd API calls.
4. **Offline Capability**: All video assets, fonts, and scripts are bundled locally for offline LAN usage.
5. **Rate Limiting**: Nginx limits submission bursts (5 req/min with burst of 3) to prevent brute-forcing.
6. **Isolated Organizer Assets**: Organizer files (`manifest.json`, `ANSWER_KEY.md`, `import_ctfd.py`) reside in `organizer_private/`, blocked by Nginx.
