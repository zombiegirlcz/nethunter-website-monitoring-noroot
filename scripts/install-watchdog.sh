#!/usr/bin/env bash
# ==========================================================================
# Install watchdogs for nethunter-TUI shadow honeypot pair.
#
# 1. Ensures PM2 is installed
# 2. Registers PM2 startup (systemd boot hook)
# 3. Saves current PM2 process list
# 4. Installs cron watchdog (every minute)
# 5. Optionally starts both instances now
# ==========================================================================

set -euo pipefail

DIR="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${DIR}/bin"
LOG_DIR="${DIR}/logs"
CRON_LOG="${HOME}/.nethunter/watchdog-cron.log"
CRON_SCRIPT="${BIN}/watchdog-cron.sh"

echo "=== Nethunter-TUI Watchdog Installer ==="
echo ""

# ── 1. Check prerequisites ──────────────────────────────────────────────
echo "[1/6] Checking prerequisites …"

if ! command -v node &>/dev/null; then
    echo "  ❌ Node.js is not installed. Install it first."
    exit 1
fi

if ! command -v npm &>/dev/null; then
    echo "  ❌ npm is not installed."
    exit 1
fi

if ! command -v pm2 &>/dev/null; then
    echo "  ⚠️  PM2 not found — installing via npm …"
    npm install -g pm2
fi

echo "  ✅ Prerequisites OK"

# ── 2. Make scripts executable ─────────────────────────────────────────
echo "[2/6] Making scripts executable …"
chmod +x "${CRON_SCRIPT}"
echo "  ✅ ${CRON_SCRIPT}"

# ── 3. Create log directories ──────────────────────────────────────────
echo "[3/6] Creating log directories …"
mkdir -p "${LOG_DIR}"
mkdir -p "${HOME}/.nethunter"
touch "${CRON_LOG}"
echo "  ✅ Log dirs ready"

# ── 4. Start both instances via PM2 ────────────────────────────────────
echo "[4/6] Starting honeypot instances via PM2 …"
cd "${DIR}"

pm2 start ecosystem.config.js --only honeypot 2>&1 || echo "  ⚠️  pm2 start honeypot had issues"
pm2 start ecosystem.config.js --only honeypot-shadow 2>&1 || echo "  ⚠️  pm2 start honeypot-shadow had issues"

echo "  ✅ PM2 instances started"

# ── 5. PM2 save + startup ──────────────────────────────────────────────
echo "[5/6] Configuring PM2 startup (systemd boot hook) …"
pm2 save 2>&1 || echo "  ⚠️  pm2 save had issues"
pm2 startup 2>&1 | tail -5 || echo "  ⚠️  pm2 startup had issues — run 'pm2 startup' manually"

echo "  ✅ PM2 persistence configured"

# ── 6. Install cron job ────────────────────────────────────────────────
echo "[6/6] Installing cron watchdog …"

CRON_LINE="* * * * * ${CRON_SCRIPT}"

# Check if cron entry already exists
if crontab -l 2>/dev/null | grep -qF "${CRON_SCRIPT}"; then
    echo "  ⏭️  Cron entry already exists — skipping"
else
    (crontab -l 2>/dev/null; echo "${CRON_LINE}") | crontab -
    echo "  ✅ Cron installed: ${CRON_LINE}"
fi

echo ""
echo "=== Install complete ==="
echo ""
echo "Quick checks:"
echo "  pm2 status                       # should show honeypot + honeypot-shadow"
echo "  cat ${CRON_LOG}                  # cron watchdog log"
echo "  ls -la ~/.nethunter/heartbeat-*  # heartbeat files"
echo ""
echo "To manually test watchdog revival:"
echo "  pm2 stop honeypot-shadow && sleep 90 && pm2 status"
echo "  # The primary's watchdog should auto-restart shadow within 30-60s"
