#!/usr/bin/env bash
# deploy.sh — FLAG THEFT AUTO · one-shot AWS bootstrap (steps 2-6 of the runbook)
#
# Run as a non-root user with sudo access on a fresh Ubuntu 24.04 EC2 instance:
#   bash deploy.sh <github-pat> <domain> <admin-email>
#
# What it does (idempotent for most steps):
#   1.  System packages: git, certbot, docker, node 20
#   2.  Swap file (2 GB) — mandatory on 1 GB t3.micro
#   3.  Clone the repo to /opt/fta  (or pull if it already exists)
#   4.  Build the React frontend
#   5.  Write .env  (secrets generated locally; prompts for POSTGRES_PASSWORD)
#   6.  Obtain a Let's Encrypt certificate via --standalone (port 80 must be free)
#   7.  Create certbot-www/ and start the production Docker Compose stack

set -euo pipefail

# ── Argument validation ───────────────────────────────────────────────────────
if [[ $# -lt 3 ]]; then
  echo "Usage: bash deploy.sh <github-pat> <domain> <admin-email>"
  echo "  github-pat    — GitHub personal-access token (repo read scope)"
  echo "  domain        — Public hostname the cert is issued for (e.g. ctf.example.com)"
  echo "  admin-email   — Contact e-mail for Let's Encrypt expiry notices"
  exit 1
fi

GH_PAT="$1"
DOMAIN="$2"
ADMIN_EMAIL="$3"
REPO="github.com/tharun7070/msrit-ctf-final.git"
INSTALL_DIR="/opt/fta"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          FLAG THEFT AUTO — production bootstrap              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo "  domain : $DOMAIN"
echo "  email  : $ADMIN_EMAIL"
echo "  dest   : $INSTALL_DIR"
echo ""

# ── 1. System packages ────────────────────────────────────────────────────────
echo "▶ [1/7] Installing system packages …"
sudo apt-get update -qq
sudo apt-get install -y -qq git certbot

if ! command -v docker &>/dev/null; then
  echo "   Installing Docker …"
  curl -fsSL https://get.docker.com | sudo sh
  sudo usermod -aG docker "$USER"
  echo "   NOTE: Docker group membership takes effect in a NEW shell."
  echo "         This script uses 'sudo docker' throughout to avoid re-login."
fi

if ! command -v node &>/dev/null; then
  echo "   Installing Node.js 20 …"
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt-get install -y -qq nodejs
fi

echo "   docker $(docker --version 2>/dev/null | head -1)"
echo "   node   $(node --version)"

# ── 2. Swap (2 GB) ───────────────────────────────────────────────────────────
echo "▶ [2/7] Configuring swap …"
if ! swapon --show | grep -q /swapfile; then
  sudo fallocate -l 2G /swapfile
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
  echo "   2 GB swap enabled."
else
  echo "   Swap already active — skipping."
fi

# ── 3. Clone / update repo ────────────────────────────────────────────────────
echo "▶ [3/7] Cloning repo → $INSTALL_DIR …"
if [[ -d "$INSTALL_DIR/.git" ]]; then
  echo "   Repo already present — pulling latest …"
  sudo git -C "$INSTALL_DIR" pull --ff-only
else
  sudo git clone "https://${GH_PAT}@${REPO}" "$INSTALL_DIR"
fi
# Allow current user to write inside the checkout
sudo chown -R "$USER:$USER" "$INSTALL_DIR"
cd "$INSTALL_DIR"

# ── 4. Build React frontend ───────────────────────────────────────────────────
echo "▶ [4/7] Building frontend …"
cd frontend
npm ci --prefer-offline --silent
npm run build
cd "$INSTALL_DIR"
echo "   dist/ ready ($(du -sh frontend/dist | cut -f1))."

# ── 5. Write .env ─────────────────────────────────────────────────────────────
echo "▶ [5/7] Writing .env …"
if [[ -f .env ]]; then
  echo "   .env already exists — leaving it untouched."
  echo "   Make sure DOMAIN=$DOMAIN is set inside it."
else
  cp .env.example .env

  # Generate secrets
  SECRET_KEY=$(openssl rand -hex 32)

  echo ""
  echo "   Enter a strong POSTGRES_PASSWORD (min 16 chars)."
  read -r -s -p "   POSTGRES_PASSWORD: " PG_PASS
  echo ""
  if [[ ${#PG_PASS} -lt 8 ]]; then
    echo "   ⚠  Password too short — using a generated one."
    PG_PASS=$(openssl rand -base64 18)
    echo "   Generated POSTGRES_PASSWORD: $PG_PASS"
    echo "   ⚠  Save this somewhere safe; it won't be shown again."
  fi

  # Patch values into .env (sed -i is safe here; lines guaranteed to exist in .env.example)
  sed -i "s|^CTFD_SECRET_KEY=.*|CTFD_SECRET_KEY=${SECRET_KEY}|"           .env
  sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${PG_PASS}|"          .env
  sed -i "s|^DOMAIN=.*|DOMAIN=${DOMAIN}|"                                 .env
  sed -i "s|^CTFD_WORKERS=.*|CTFD_WORKERS=2|"                             .env
  # Keep EVENT_START at the value from .env.example (edit manually if needed)

  echo "   .env written."
  echo "   ⚠  Edit CTFD_TOKEN after the CTFd wizard completes (step 7 of runbook)."
fi

# ── 6. TLS certificate ────────────────────────────────────────────────────────
echo "▶ [6/7] Obtaining Let's Encrypt certificate …"
CERT_PATH="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
if [[ -f "$CERT_PATH" ]]; then
  echo "   Certificate already present — skipping certbot."
else
  # Port 80 must be free; nothing else should be running yet.
  if sudo ss -tlnp | grep -q ':80 '; then
    echo ""
    echo "   ✗  Something is already listening on port 80."
    echo "      Stop it and re-run this script, or obtain the cert manually:"
    echo "      sudo certbot certonly --standalone -d ${DOMAIN} --agree-tos -m ${ADMIN_EMAIL} --no-eff-email"
    echo ""
    exit 1
  fi
  sudo certbot certonly \
    --standalone \
    -d "$DOMAIN" \
    --agree-tos \
    -m "$ADMIN_EMAIL" \
    --no-eff-email \
    --non-interactive
  echo "   ✔ Certificate issued → /etc/letsencrypt/live/${DOMAIN}/"
fi

# ── 7. Launch prod stack ──────────────────────────────────────────────────────
echo "▶ [7/7] Starting production Docker Compose stack …"
mkdir -p certbot-www

# Docker may need sudo if the current shell session pre-dates the docker group add
DOCKER_CMD="sudo docker"
if docker info &>/dev/null 2>&1; then
  DOCKER_CMD="docker"
fi

$DOCKER_CMD compose -f docker-compose.prod.yml up -d --build

echo ""
echo "   Waiting 20 s for services to become healthy …"
sleep 20
$DOCKER_CMD compose -f docker-compose.prod.yml ps

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                   Bootstrap complete!                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Next steps (runbook §7-9):"
echo ""
echo "  1. Open https://${DOMAIN}/ and complete the CTFd setup wizard."
echo "     (name: FLAG THEFT AUTO, mode: Teams, max size: 3)"
echo ""
echo "  2. Admin → Settings → Access Tokens → Generate."
echo "     Paste the token into .env as CTFD_TOKEN=<token>"
echo ""
echo "  3. Import challenges + provision teams:"
echo ""
echo "     $DOCKER_CMD compose -f docker-compose.prod.yml run --rm \\"
echo "       -e CTFD_URL=http://ctfd:8000 -e CTFD_TOKEN=<token> bonus-reveal \\"
echo "       python import_ctfd.py --apply --allow-http"
echo ""
echo "     $DOCKER_CMD compose -f docker-compose.prod.yml run --rm \\"
echo "       -e CTFD_URL=http://ctfd:8000 -e CTFD_TOKEN=<token> bonus-reveal \\"
echo "       python import_ctfd.py --apply --allow-http --bonus"
echo ""
echo "     $DOCKER_CMD compose -f docker-compose.prod.yml run --rm \\"
echo "       -e CTFD_URL=http://ctfd:8000 -e CTFD_TOKEN=<token> bonus-reveal \\"
echo "       python provision_teams.py --roster /app/roster.csv --apply --allow-http"
echo ""
echo "  4. Restart bonus-reveal so it picks up the token:"
echo "     $DOCKER_CMD compose -f docker-compose.prod.yml up -d --force-recreate bonus-reveal"
echo ""
echo "  5. Cert renewal (every 60-90 days):"
echo "     sudo certbot renew --webroot -w /opt/fta/certbot-www"
echo "     $DOCKER_CMD compose -f docker-compose.prod.yml exec nginx nginx -s reload"
echo ""
