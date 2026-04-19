#!/usr/bin/env bash
# =============================================================================
#  CASB Gateway — Stop Script
#  Kills: LiteLLM Proxy + Dashboard Server
#  Restores: Continue config to normal (direct) mode
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✔]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

echo -e "\n${CYAN}  🛡️  CASB Gateway — Shutdown${NC}\n"

# ── Kill processes ─────────────────────────────────────────────────────────
pkill -f litellm         2>/dev/null && log "LiteLLM proxy stopped"       || warn "LiteLLM was not running"
pkill -f dashboard_server 2>/dev/null && log "Dashboard server stopped"   || warn "Dashboard was not running"

# ── Restore Continue config ────────────────────────────────────────────────
CONTINUE_CFG="$HOME/.continue/config.yaml"
CONTINUE_BACKUP="$SCRIPT_DIR/backups/continue_normal_config.yaml"

if [[ -f "$CONTINUE_BACKUP" ]]; then
  cp "$CONTINUE_BACKUP" "$CONTINUE_CFG"
  log "Continue config restored to normal (direct) mode"
else
  warn "No backup found at $CONTINUE_BACKUP — Continue config unchanged"
fi

echo ""
log "CASB Gateway fully stopped. Continue/Cline now connect directly to Ollama & LM Studio."
