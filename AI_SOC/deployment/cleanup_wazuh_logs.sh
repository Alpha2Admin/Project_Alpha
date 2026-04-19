#!/bin/bash
# /opt/wazuh/cleanup_logs.sh
# Runs every 4 hours via cron - keeps disk usage safe on the Wazuh VM.
# Cleans: Wazuh archive logs, Docker container logs, old queue files.

LOG_FILE="/var/log/casb_cleanup.log"
THRESHOLD=70  # Warn if disk still above this % after cleanup
WAZUH_CONTAINER="single-node-wazuh.manager-1"
COMPOSE_DIR="/opt/wazuh/wazuh-docker/single-node"

echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] === AI-CASB Log Cleanup Started ===" >> "$LOG_FILE"

# ── 1. Wazuh archive logs inside the container (keep < 24h) ──────────────────
echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] Clearing Wazuh archive logs..." >> "$LOG_FILE"
docker exec "$WAZUH_CONTAINER" bash -c \
  "find /var/ossec/logs/archives/ -type f -mmin +240 -delete 2>/dev/null; \
   find /var/ossec/logs/alerts/   -type f -mmin +240 -delete 2>/dev/null; \
   find /var/ossec/logs/          -type f -name '*.gz' -mmin +240 -delete 2>/dev/null" \
  2>> "$LOG_FILE" && echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] Wazuh logs cleared." >> "$LOG_FILE"

# ── 2. Docker container logs (truncate all to 0 bytes) ───────────────────────
echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] Truncating Docker container logs..." >> "$LOG_FILE"
find /var/lib/docker/containers/ -type f -name '*.log' \
  -exec truncate -s 0 {} \; 2>> "$LOG_FILE"
echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] Docker logs truncated." >> "$LOG_FILE"

# ── 3. Wazuh queue safety net (clear OLD DATA only if queue > 5GB) ───────────
QUEUE_SIZE=$(du -sb /var/lib/docker/volumes/single-node_wazuh_queue/_data 2>/dev/null | cut -f1)
QUEUE_LIMIT=$((5 * 1024 * 1024 * 1024))  # 5GB
if [ "${QUEUE_SIZE:-0}" -gt "$QUEUE_LIMIT" ]; then
  echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] Queue bloat detected (${QUEUE_SIZE} bytes) — safe clearing..." >> "$LOG_FILE"
  docker compose -f "$COMPOSE_DIR/docker-compose.yml" stop wazuh.manager 2>> "$LOG_FILE"
  # SAFE: only delete files inside data subdirs, never delete the dirs themselves
  # Preserve: db/, sockets/, fts/ (critical for daemon startup)
  find /var/lib/docker/volumes/single-node_wazuh_queue/_data/alerts/   -type f -delete 2>/dev/null
  find /var/lib/docker/volumes/single-node_wazuh_queue/_data/syscheck/ -type f -delete 2>/dev/null
  find /var/lib/docker/volumes/single-node_wazuh_queue/_data/diff/     -type f -delete 2>/dev/null
  find /var/lib/docker/volumes/single-node_wazuh_queue/_data/rids/     -type f -delete 2>/dev/null
  docker compose -f "$COMPOSE_DIR/docker-compose.yml" start wazuh.manager 2>> "$LOG_FILE"
  echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] Queue safely cleared and manager restarted." >> "$LOG_FILE"
fi


# ── 4. systemd journal vacuum ─────────────────────────────────────────────────
journalctl --vacuum-time=4h >> "$LOG_FILE" 2>&1

# ── 5. Disk usage check ───────────────────────────────────────────────────────
DISK_PCT=$(df / | awk 'NR==2 {print $5}' | tr -d '%')
echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] Disk usage after cleanup: ${DISK_PCT}%" >> "$LOG_FILE"
if [ "$DISK_PCT" -gt "$THRESHOLD" ]; then
  echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] ⚠️  WARNING: Disk still at ${DISK_PCT}% after cleanup!" >> "$LOG_FILE"
fi

echo "[$(date -u '+%Y-%m-%dT%H:%M:%SZ')] === Cleanup Complete ===" >> "$LOG_FILE"
