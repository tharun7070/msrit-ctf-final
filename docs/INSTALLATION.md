# FLAG THEFT AUTO — Installation & Quick Start

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Node.js | 20+ | Frontend build |
| pnpm or npm | latest | Package manager |
| Docker Desktop | 4.x+ | CTFd + database |
| Python | 3.9+ | Challenge importer |

---

## Option A — Full Docker Compose (Recommended for Event Day)

### 1. Build the React frontend

```powershell
# From d:\ctf\FLAG_THEFT_AUTO_FINAL\frontend\
npm install
npm run build
```

### 2. Configure environment

```powershell
Copy-Item .env.example .env
# Edit .env with a real CTFD_SECRET_KEY and POSTGRES_PASSWORD
```

### 3. Start the full stack

```powershell
# From d:\ctf\FLAG_THEFT_AUTO_FINAL\
docker compose up -d
```

This starts:
- **CTFd** at http://localhost:8000
- **PostgreSQL** database (internal)
- **Redis** cache (internal)
- **Nginx** reverse proxy at http://localhost:80 (serves React SPA + proxies API)

### 4. Complete CTFd setup wizard

Open http://localhost:8000 and follow the setup wizard:
- Competition name: `FLAG THEFT AUTO`
- Mode: `Teams`
- Team size max: `3`
- Registration: `Open` (or restricted by token for the event)

### 5. Import challenges

```powershell
# Get your admin token from CTFd admin panel → Settings → Access Tokens
# Then set env variable (PowerShell):
$env:CTFD_TOKEN = "your_actual_token_here"
$env:CTFD_URL   = "http://localhost:8000"

# Dry run first (validates without importing):
python d:\ctf\FLAG_THEFT_AUTO_ORGANIZER_PRIVATE\ORGANIZER\CTFD_IMPORT\import_ctfd.py

# Import all 15 challenges:
python d:\ctf\FLAG_THEFT_AUTO_ORGANIZER_PRIVATE\ORGANIZER\CTFD_IMPORT\import_ctfd.py --apply --allow-http
```

### 6. Access the site

| URL | Purpose |
|-----|---------|
| http://localhost | FLAG THEFT AUTO landing page (cinematic) |
| http://localhost/login | Crew login |
| http://localhost/register | Join the underground |
| http://localhost/dashboard | Player HUD (authenticated) |
| http://localhost/missions | Mission board |
| http://localhost/leaderboard | Live leaderboard |
| http://localhost:8000/admin | CTFd admin panel |

---

## Option B — Development Mode (Separate processes)

### 1. Start CTFd (Docker)

```powershell
docker compose up db cache ctfd -d
```

### 2. Start React dev server

```powershell
cd d:\ctf\FLAG_THEFT_AUTO_FINAL\frontend
npm install
npm run dev
```

The Vite dev server starts at http://localhost:3000 and proxies all `/api/` requests to CTFd at port 8000.

---

## Stopping Everything

```powershell
docker compose down           # Stop containers
docker compose down -v        # Stop + delete all data (WARNING: resets CTFd)
```

---

## Troubleshooting

### CTFd not starting
```powershell
docker compose logs ctfd
```

### Database connection error
```powershell
docker compose logs db
docker compose restart ctfd
```

### Challenge import fails
- Ensure CTFd setup wizard is complete before importing
- Check that challenges don't already exist (import requires a fresh board)
- Verify `CTFD_TOKEN` environment variable is set

### Nginx 502 Bad Gateway
CTFd may still be starting. Wait 30 seconds and refresh.

### Videos not playing
Ensure `frontend/public/videos/` contains all 4 MP4 files from the reference project.
