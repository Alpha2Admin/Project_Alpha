#!/usr/bin/env bash
# =============================================================================
#  CASB Gateway — Unified Startup Script
#  Starts: LiteLLM Proxy (port 4000) + Dashboard Server (port 5001)
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
VENV="$SCRIPT_DIR/venv/bin"

# Colours
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'

banner() {
  echo -e "\n${CYAN}=============================================${NC}"
  echo -e "${CYAN}  🛡️  CASB Gateway — Startup${NC}"
  echo -e "${CYAN}=============================================${NC}\n"
}

log()   { echo -e "${GREEN}[✔]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✘]${NC} $*"; exit 1; }

# ── Preflight ──────────────────────────────────────────────────────────────
banner

cd "$SCRIPT_DIR"

[[ -f ".env" ]]               || error ".env not found. Please create it first."
[[ -f "config.yaml" ]]        || error "config.yaml not found."
[[ -f "dashboard_server.py" ]] || error "dashboard_server.py not found."
[[ -x "$VENV/litellm" ]]      || error "venv not set up. Run deploy_cloud_lab.sh first."
[[ -f "dlp_rules.json" ]]     || error "dlp_rules.json not found."

# Load environment
set -a; source .env; set +a
log "Environment loaded"

# ── Swap Continue config to CASB-secured mode ─────────────────────────────
CONTINUE_CFG="$HOME/.continue/config.yaml"
CONTINUE_BACKUP="$SCRIPT_DIR/backups/continue_normal_config.yaml"
CASB_CFG="$SCRIPT_DIR/backups/continue_casb_config.yaml"

if [[ -f "$CASB_CFG" ]]; then
  # Back up the current (normal) config if it's not already a CASB config
  if ! grep -q "CASB" "$CONTINUE_CFG" 2>/dev/null; then
    cp "$CONTINUE_CFG" "$CONTINUE_BACKUP" 2>/dev/null && \
      log "Continue normal config backed up"
  fi
  cp "$CASB_CFG" "$CONTINUE_CFG"
  log "Continue config switched to CASB-secured mode"
else
  warn "No CASB Continue config found at $CASB_CFG — skipping swap"
fi

# Ensure Flask is installed
"$VENV/pip" show flask &>/dev/null || {
  warn "Flask not found — installing..."
  "$VENV/pip" install flask -q
}

# ── Ensure Splunk is running ───────────────────────────────────────────────
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "splunk_casb"; then
  log "Splunk container already running"
else
  warn "Starting Splunk container..."
  docker start splunk_casb 2>/dev/null || warn "Could not start Splunk — check Docker"
fi

# ── Create log directory ───────────────────────────────────────────────────
mkdir -p "$LOG_DIR"

# ── Kill existing processes on our ports ──────────────────────────────────
for port in 4000 5001 8080; do
  pid=$(lsof -ti tcp:$port 2>/dev/null || true)
  if [[ -n "$pid" ]]; then
    warn "Port $port in use by PID $pid — stopping..."
    kill -9 "$pid" 2>/dev/null || true
    sleep 1
  fi
done

# ── Start CASB Dashboard (port 5001) ──────────────────────────────────────
log "Starting CASB Dashboard on port 5001..."
nohup "$VENV/python" "$SCRIPT_DIR/dashboard_server.py" \
  > "$LOG_DIR/dashboard.log" 2>&1 &
DASHBOARD_PID=$!
echo "$DASHBOARD_PID" > "$LOG_DIR/dashboard.pid"
sleep 2

# Verify dashboard is up
if curl -s http://localhost:5001/api/rules &>/dev/null; then
  log "Dashboard running  → http://localhost:5001  (PID: $DASHBOARD_PID)"
else
  error "Dashboard failed to start. Check $LOG_DIR/dashboard.log"
fi

# ── Start Copilot Forward Proxy (port 8080) ───────────────────────────────
log "Starting Copilot Mitmproxy on port 8080..."
nohup "$VENV/mitmdump" -s "$SCRIPT_DIR/copilot_interceptor.py" --set block_global=false \
  --set http2=false --ignore-hosts 'api\.github\.com' --ignore-hosts '.*\.(microsoft|azure)\.com' \
  > "$LOG_DIR/mitmproxy.log" 2>&1 &
MITMPROXY_PID=$!
echo "$MITMPROXY_PID" > "$LOG_DIR/mitmproxy.pid"
sleep 2

CA_CERT_PATH="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
if [[ -f "$CA_CERT_PATH" ]]; then
  export NODE_EXTRA_CA_CERTS="$CA_CERT_PATH"
  log "NODE_EXTRA_CA_CERTS exported for Copilot interception"
else
  warn "mitmproxy certificate not found, Copilot SSL inspection may fail."
fi

# ── Start LiteLLM Proxy (port 4000) ───────────────────────────────────────
echo ""
echo -e "${CYAN}=============================================${NC}"
echo -e "${CYAN}  Launching AI-CASB Security Gateway${NC}"
echo -e "${CYAN}  Dashboard → http://localhost:5001${NC}"
echo -e "${CYAN}  LiteLLM   → http://localhost:4000 (Reverse Proxy)${NC}"
echo -e "${CYAN}  Copilot   → http://localhost:8080 (Forward Proxy)${NC}"
echo -e "${CYAN}  CA Cert   → $CA_CERT_PATH${NC}"
echo -e "${CYAN}  Press Ctrl+C to stop everything${NC}"
echo -e "${CYAN}=============================================${NC}\n"

# Trap Ctrl+C to clean up all processes
cleanup() {
  echo -e "\n${YELLOW}[!] Shutting down CASB Gateway...${NC}"
  kill "$DASHBOARD_PID" 2>/dev/null && log "Dashboard stopped"
  kill "$MITMPROXY_PID" 2>/dev/null && log "Copilot Mitmproxy stopped"
  # Restore normal Continue config
  if [[ -f "$CONTINUE_BACKUP" ]]; then
    cp "$CONTINUE_BACKUP" "$CONTINUE_CFG"
    log "Continue config restored to normal (direct) mode"
  fi
  log "LiteLLM stopped"
  exit 0
}
trap cleanup SIGINT SIGTERM

# Run LiteLLM in foreground (keeps terminal alive, shows live logs)
"$VENV/litellm" --config "$SCRIPT_DIR/config.yaml" --port 4000
