#!/usr/bin/env bash
# ==========================================================================
# Cron watchdog for nethunter-TUI shadow honeypot pair.
#
# Runs every minute via crontab. Checks:
#   1. PM2 status of both "honeypot" and "honeypot-shadow"
#   2. Heartbeat freshness for both instances
#
# If any check fails, restarts the dead instance via PM2.
# Logs to ~/.nethunter/watchdog-cron.log
#
# Install with:  crontab -e
#   * * * * * /home/kali/nethunter-TUI/bin/watchdog-cron.sh
# ==========================================================================

set -uo pipefail

LOG="${HOME}/.nethunter/watchdog-cron.log"
DIR="$(cd "$(dirname "$0")/.." && pwd)"
ECOSYSTEM="${DIR}/ecosystem.config.js"
TTL=90   # max heartbeat age in seconds — generous for cron (1 min + margin)

mkdir -p "${HOME}/.nethunter"
echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] watchdog-cron: starting check" >> "$LOG"

# ── 1. Check PM2 is available ────────────────────────────────────────
if ! command -v pm2 &>/dev/null; then
    echo "  FAIL: pm2 not on PATH" >> "$LOG"
    exit 1
fi

# ── 2. Check PM2 status of both instances ────────────────────────────
for NAME in honeypot honeypot-shadow; do
    STATUS=$(pm2 jlist 2>/dev/null | python3 -c "
import sys, json
try:
    procs = json.load(sys.stdin)
    for p in procs:
        if p.get('name') == '$NAME':
            print(p.get('pm2_env', {}).get('status', 'unknown'))
            sys.exit(0)
    print('stopped')
except Exception:
    print('unknown')
" 2>/dev/null)

    if [ "$STATUS" != "online" ]; then
        echo "  FAIL: $NAME status=$STATUS — restarting via PM2" >> "$LOG"
        pm2 start "$ECOSYSTEM" --only "$NAME" 2>&1 | head -5 >> "$LOG"
    else
        echo "  OK:   $NAME status=$STATUS" >> "$LOG"
    fi
done

# ── 3. Check heartbeat freshness ─────────────────────────────────────
for INSTANCE in primary shadow; do
    HB_FILE="${HOME}/.nethunter/heartbeat-${INSTANCE}.ts"
    if [ ! -f "$HB_FILE" ]; then
        echo "  FAIL: heartbeat-$INSTANCE missing" >> "$LOG"
        # Map instance to PM2 name
        if [ "$INSTANCE" = "primary" ]; then
            pm2 start "$ECOSYSTEM" --only honeypot 2>&1 | head -3 >> "$LOG"
        else
            pm2 start "$ECOSYSTEM" --only honeypot-shadow 2>&1 | head -3 >> "$LOG"
        fi
        continue
    fi

    HB_TS=$(cat "$HB_FILE" 2>/dev/null | tr -d ' \n')
    NOW=$(date +%s)
    AGE=$(( NOW - HB_TS ))

    if [ "$AGE" -gt "$TTL" ]; then
        echo "  FAIL: heartbeat-$INSTANCE age=${AGE}s > TTL=${TTL}s — restarting" >> "$LOG"
        if [ "$INSTANCE" = "primary" ]; then
            pm2 start "$ECOSYSTEM" --only honeypot 2>&1 | head -3 >> "$LOG"
        else
            pm2 start "$ECOSYSTEM" --only honeypot-shadow 2>&1 | head -3 >> "$LOG"
        fi
    else
        echo "  OK:   heartbeat-$INSTANCE age=${AGE}s" >> "$LOG"
    fi
done

echo "watchdog-cron: check complete" >> "$LOG"
