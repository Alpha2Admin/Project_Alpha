#!/usr/bin/env bash
###############################################################################
#  Cloud-Only AI Security Gateway (CASB) — Teardown Script
#  ========================================================
#  Cleanly stops and removes all containers, the Python venv, and generated
#  config files created by deploy_cloud_lab.sh.
#
#  Usage:  bash teardown_cloud_lab.sh
###############################################################################
set -euo pipefail

# ---------------------------------------------------------------------------
# Helper: print a section banner
# ---------------------------------------------------------------------------
banner() {
  echo ""
  echo "============================================================"
  echo "  $1"
  echo "============================================================"
  echo ""
}

pass() { echo "  ✅  $1"; }
warn() { echo "  ⚠️   $1"; }

# Navigate to script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

banner "🧹 Cloud AI CASB — Teardown"

# --- 1. Stop and remove the Splunk container --------------------------------
echo "🐳  Stopping and removing splunk_casb container..."
if docker ps -a --format '{{.Names}}' | grep -q "^splunk_casb$"; then
  docker stop splunk_casb 2>/dev/null || true
  docker rm splunk_casb 2>/dev/null || true
  pass "Container 'splunk_casb' stopped and removed."
else
  warn "Container 'splunk_casb' not found — nothing to remove."
fi

# --- 2. Remove the Python virtual environment --------------------------------
echo ""
echo "🐍  Removing Python virtual environment..."
if [[ -d venv ]]; then
  rm -rf venv
  pass "venv/ removed."
else
  warn "venv/ not found — nothing to remove."
fi

# --- 3. Remove generated config files ----------------------------------------
echo ""
echo "🗑️   Removing generated config files..."
for FILE in config.yaml custom_callbacks.py .env; do
  if [[ -f "$FILE" ]]; then
    rm -f "$FILE"
    pass "$FILE removed."
  else
    warn "$FILE not found — nothing to remove."
  fi
done

# --- Done --------------------------------------------------------------------
banner "✅ Teardown Complete"

cat << 'EOF'
  All CASB components have been cleaned up:

    • splunk_casb container  — stopped & removed
    • venv/                  — deleted
    • config.yaml            — deleted
    • custom_callbacks.py    — deleted
    • .env                   — deleted

  To redeploy, run:  bash deploy_cloud_lab.sh
EOF

echo ""
