# FLAG THEFT AUTO — Production Deployment Guide

## Production Deployment Topology

FLAG THEFT AUTO is designed to deploy on a single dedicated machine or server on a local area network (LAN) without requiring public internet access during competition time.

```
                      COLLEGE WI-FI / LAN ROUTER
                                  │
                  ┌───────────────┴───────────────┐
                  │                               │
        TEAM 1 LAPTOPS                     TEAM 25 LAPTOPS
    http://192.168.1.100                http://192.168.1.100
                  │                               │
                  └───────────────┬───────────────┘
                                  ▼
                         COMPETITION SERVER
                         (IP: 192.168.1.100)
                                  │
                          NGINX (Port 80)
                                  │
                    ┌─────────────┴─────────────┐
                    ▼                           ▼
          React Static Assets             CTFd Backend
            (Vite Bundle)                  (Port 8000)
                                                │
                                    ┌───────────┴───────────┐
                                    ▼                       ▼
                              PostgreSQL 15              Redis 7
```

## Step-by-Step Deployment Instructions

### 1. Build Production Frontend
```powershell
cd d:\ctf\FLAG_THEFT_AUTO_FINAL\frontend
npm run build
```
This produces `d:\ctf\FLAG_THEFT_AUTO_FINAL\frontend\dist` containing all minified JS, CSS, fonts, images, and videos.

### 2. Configure Environment Variables
```powershell
cd d:\ctf\FLAG_THEFT_AUTO_FINAL
Copy-Item .env.example .env
```
Edit `.env`:
- Set `CTFD_SECRET_KEY` to a 64-character random string.
- Set `POSTGRES_PASSWORD` to a strong unique password.

### 3. Launch Docker Compose Stack
```powershell
docker compose up -d
```
Verify all 4 containers are healthy:
```powershell
docker compose ps
```

### 4. Initialize CTFd Instance
1. Open `http://<SERVER_IP>/` in your browser.
2. Complete the setup wizard:
   - Competition Name: `FLAG THEFT AUTO`
   - User Mode: `Teams`
   - Team Size Limit: `3`
   - Admin account credentials: save securely.
3. In the CTFd Admin panel, go to `Settings` -> `Access Tokens` and generate an Admin API token.

### 5. Import All 25 Challenges
```powershell
$env:CTFD_TOKEN = "your_generated_admin_token"
$env:CTFD_URL = "http://localhost:8000"
python scripts/import_challenges.py --apply --allow-http
```

### 6. Provision Crew Credentials
Public registration is closed. Create one team + member logins per crew and emit a private credentials sheet:
```powershell
python organizer_private\CTFD_IMPORT\provision_teams.py --roster roster.csv --apply --allow-http
```
`roster.csv` is one row per crew: `team_name,member1[,member2][,member3]`. Credentials land in `organizer_private\team_credentials.csv` — distribute one row-group per crew.

### 7. Verify Deployment Health
Run the automated verification suite:
```powershell
python scripts/validate_challenges.py
```
Open `http://<SERVER_IP>/` from a participant device to verify responsive layout, video playback, and challenge browsing.
