#!/usr/bin/env bash
###############################################################################
#  AI-CASB — Automated Deployment Script
#  =====================================================================
#  Routes all IDE AI traffic through a local LiteLLM proxy to LM Studio
#  or Ollama, enforces DLP guardrails, and logs telemetry to a local
#  Splunk Enterprise instance for security observability.
#
#  Usage:  chmod +x deploy_cloud_lab.sh && ./deploy_cloud_lab.sh
#  Teardown: ./teardown_cloud_lab.sh
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

# ---------------------------------------------------------------------------
# Helper: print status icons
# ---------------------------------------------------------------------------
pass() { echo "  ✅  $1"; }
fail() { echo "  ❌  $1"; }
warn() { echo "  ⚠️   $1"; }

###############################################################################
#  STEP 1 — Bootstrap & Preflight Checks
###############################################################################
banner "[STEP 1] Bootstrap & Preflight Checks"

# --- 1a. Ensure we are inside cloud-sec-gateway ----------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
echo "📂  Working directory: $(pwd)"

# --- 1b. Docker installed & daemon running ---------------------------------
echo ""
echo "🔍  Checking Docker..."
if ! command -v docker &>/dev/null; then
  fail "Docker is not installed. Please install Docker first."
  exit 1
fi

if ! docker info &>/dev/null; then
  fail "Docker daemon is not running. Start it with: sudo systemctl start docker"
  exit 1
fi
pass "Docker is installed and the daemon is running."

# --- 1c. Python 3.10+ available --------------------------------------------
echo ""
echo "🔍  Checking Python version..."
if ! command -v python3 &>/dev/null; then
  fail "Python 3 is not installed."
  exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [[ "$PYTHON_MAJOR" -lt 3 ]] || { [[ "$PYTHON_MAJOR" -eq 3 ]] && [[ "$PYTHON_MINOR" -lt 10 ]]; }; then
  fail "Python 3.10+ is required. Found: Python $PYTHON_VERSION"
  exit 1
fi
pass "Python $PYTHON_VERSION detected (≥ 3.10)."

# --- 1d. Required ports are free (8000, 8088, 4000) ------------------------
echo ""
echo "🔍  Checking port availability..."
PORTS_TO_CHECK=(8000 8088 4000)
for PORT in "${PORTS_TO_CHECK[@]}"; do
  if ss -tulnp 2>/dev/null | grep -q ":${PORT} " || \
     (command -v lsof &>/dev/null && lsof -iTCP:"${PORT}" -sTCP:LISTEN &>/dev/null); then
    fail "Port $PORT is already in use. Free it before running this script."
    exit 1
  fi
  pass "Port $PORT is available."
done

# --- 1e. Check for conflicting config files --------------------------------
echo ""
echo "🔍  Checking for existing config files..."
CONFLICT=false
for FILE in config.yaml custom_callbacks.py; do
  if [[ -f "$FILE" ]]; then
    warn "$FILE already exists in $(pwd)."
    CONFLICT=true
  fi
done

if [[ "$CONFLICT" == "true" ]]; then
  echo ""
  read -r -p "⚠️  Existing config files detected. Overwrite? [y/N] " CONFIRM
  CONFIRM="${CONFIRM:-N}"
  if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    echo "Aborting. Remove or rename the conflicting files and re-run."
    exit 1
  fi
  echo "Proceeding with overwrite..."
fi

pass "Preflight checks passed."

###############################################################################
#  STEP 2 — Environment File Generation
###############################################################################
banner "[STEP 2] Generating .env file"

# Generate the .env file with explanatory comments.
# ⚠️  NEVER commit .env to version control — add it to .gitignore!
cat << 'EOF' > .env
###############################################################################
#  AI-CASB — Environment Variables
# ---------------------------------------------------------------------------
#  SPLUNK_HEC_TOKEN      : HTTP Event Collector token (create in Splunk UI)
#  SPLUNK_PASSWORD        : Password for the Splunk admin account
#  LITELLM_MASTER_KEY    : Bearer token that locks the LiteLLM proxy
#
#  ⚠️  NEVER commit this file to version control!
#      Add ".env" to your .gitignore immediately.
###############################################################################
SPLUNK_HEC_TOKEN="REPLACE_AFTER_SPLUNK_SETUP"
SPLUNK_PASSWORD="REPLACE_WITH_YOUR_SPLUNK_PASSWORD"
LITELLM_MASTER_KEY="REPLACE_WITH_A_RANDOM_SECRET"
EOF

# Lock down permissions — owner read/write only
chmod 600 .env
pass ".env created with mode 600 (owner-only read/write)."

# Source the env file into the current shell
set -a
# shellcheck disable=SC1091
source .env
set +a
pass "Environment variables loaded into the current shell."

# Create .gitignore if it doesn't exist, or append .env to it
if [[ -f .gitignore ]]; then
  if ! grep -q "^\.env$" .gitignore; then
    echo ".env" >> .gitignore
    pass "Appended .env to existing .gitignore."
  fi
else
  echo ".env" > .gitignore
  pass "Created .gitignore with .env entry."
fi

###############################################################################
#  STEP 3 — Splunk Container
###############################################################################
banner "[STEP 3] Starting Splunk Enterprise Container"

# Check if the container already exists (running or stopped)
if docker ps -a --format '{{.Names}}' | grep -q "^splunk_casb$"; then
  warn "Container 'splunk_casb' already exists — skipping creation."
  # If it exists but is stopped, start it
  if ! docker ps --format '{{.Names}}' | grep -q "^splunk_casb$"; then
    echo "  ↻  Container exists but is stopped. Starting it..."
    docker start splunk_casb
  fi
else
  echo "🚀  Launching Splunk container..."
  docker run -d \
    -p 8000:8000 \
    -p 8088:8088 \
    -e "SPLUNK_START_ARGS=--accept-license" \
    -e "SPLUNK_GENERAL_TERMS=--accept-sgt-current-at-splunk-com" \
    -e "SPLUNK_PASSWORD=${SPLUNK_PASSWORD}" \
    --name splunk_casb \
    --restart unless-stopped \
    splunk/splunk:latest
  pass "Splunk container started."
fi

# --- Health-check loop: wait for Splunk web UI to respond -------------------
echo ""
echo "⏳  Waiting for Splunk to become healthy (up to 120 s)..."
MAX_ATTEMPTS=12
ATTEMPT=0
SPLUNK_HEALTHY=false

while [[ $ATTEMPT -lt $MAX_ATTEMPTS ]]; do
  ATTEMPT=$((ATTEMPT + 1))
  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8000 2>/dev/null || echo "000")

  if [[ "$HTTP_CODE" == "200" || "$HTTP_CODE" == "303" ]]; then
    SPLUNK_HEALTHY=true
    break
  fi

  echo "  ⏳  Waiting for Splunk... attempt ${ATTEMPT}/${MAX_ATTEMPTS} (HTTP ${HTTP_CODE})"
  sleep 10
done

if [[ "$SPLUNK_HEALTHY" == "true" ]]; then
  pass "Splunk is healthy and responding on http://localhost:8000."
else
  warn "Splunk did not respond within 120 s. It may still be booting."
  warn "Verify manually at http://localhost:8000 before proceeding."
  echo "  (The script will continue — Splunk is not a hard dependency for setup.)"
fi

###############################################################################
#  STEP 4 — Python Virtual Environment & Dependencies
###############################################################################
banner "[STEP 4] Creating Python venv & Installing Dependencies"

# Create venv (use python3 directly, never 'source activate')
if [[ -d venv ]]; then
  warn "venv/ already exists — reusing it."
else
  python3 -m venv venv
  pass "Virtual environment created at ./venv"
fi

# Upgrade pip first
echo "📦  Upgrading pip..."
./venv/bin/pip install --upgrade pip --quiet

# Install dependencies with fallback
echo "📦  Installing dependencies (litellm, fastapi, aiohttp)..."
if ./venv/bin/pip install litellm 'litellm[proxy]' requests fastapi aiohttp --quiet; then
  pass "All dependencies installed successfully."
else
  warn "Full install failed — retrying without extras..."
  ./venv/bin/pip install litellm requests fastapi aiohttp --quiet
  pass "Dependencies installed (without litellm[proxy] extras)."
fi

###############################################################################
#  STEP 5 — LiteLLM Proxy Configuration
###############################################################################
banner "[STEP 5] Generating LiteLLM config.yaml"

# master_key    — locks the proxy; only requests with the correct bearer token
#                 are accepted.
# max_input_tokens — hard ceiling to prevent prompt-stuffing attacks.
# drop_params   — silently removes unsupported params instead of erroring.
cat << 'EOF' > config.yaml
model_list:
  # Wildcard: routes any model request to LM Studio (port 1234)
  - model_name: "*"
    litellm_params:
      model: "openai/*"
      api_base: "http://localhost:1234/v1"
      api_key: "not-needed"

litellm_settings:
  master_key: "os.environ/LITELLM_MASTER_KEY"
  callbacks: ["custom_callbacks.proxy_handler_instance"]
  request_timeout: 60
  drop_params: true
  disable_spend_logs: true
  store_model_in_db: false

general_settings:
  max_input_tokens: 8000
  store_model_in_db: false
EOF

pass "config.yaml generated."

###############################################################################
#  STEP 6 — DLP Guardrail & Splunk Logging Callback
###############################################################################
banner "[STEP 6] Generating custom_callbacks.py (DLP + Splunk Logger)"

cat << 'EOF' > custom_callbacks.py
import re
import os
import json
import aiohttp
import asyncio
import urllib3
from litellm.integrations.custom_logger import CustomLogger
from fastapi import HTTPException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_HEC_URL = "https://localhost:8088/services/collector/event"
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "YOUR_TOKEN_HERE")

# --- DLP Policy Rules ---
DLP_RULES = [
    {
        "name": "Internal IPv4 Address",
        "pattern": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        "detail": "CASB Policy Violation: IP Addresses are not permitted in prompts."
    },
    {
        "name": "Hardcoded Credential",
        "pattern": r'(?i)(password|secret|api_key|token)\s*=\s*["\'][a-zA-Z0-9\-_]{10,}["\']',
        "detail": "CASB Policy Violation: Hardcoded credentials are not permitted in prompts."
    },
    {
        "name": "Credit Card Number",
        "pattern": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b',
        "detail": "CASB Policy Violation: Credit card numbers are not permitted in prompts."
    },
    {
        "name": "AWS Access Key",
        "pattern": r'(?i)(AKIA|ASIA|AROA)[A-Z0-9]{16}',
        "detail": "CASB Policy Violation: AWS access keys are not permitted in prompts."
    },
    {
        "name": "Private Key Block",
        "pattern": r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
        "detail": "CASB Policy Violation: Private keys are not permitted in prompts."
    },
    {
        "name": "Email Address (PII)",
        "pattern": r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b',
        "detail": "CASB Policy Violation: Email addresses (PII) are not permitted in prompts."
    },
]

class SecOpsGateway(CustomLogger):

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        prompt_str = str(data.get("messages", []))

        # Hard cap on prompt size to prevent prompt-stuffing
        if len(prompt_str) > 32000:
            print("\n🚨 [CASB ALERT] BLOCKED: Prompt exceeds maximum allowed size.")
            raise HTTPException(status_code=413, detail="CASB Policy Violation: Prompt too large.")

        # Run all DLP rules
        for rule in DLP_RULES:
            if re.search(rule["pattern"], prompt_str):
                print(f"\n🚨 [CASB ALERT] BLOCKED: {rule['name']} detected!")
                await self._log_to_splunk({
                    "action": "dlp_block",
                    "rule": rule["name"],
                    "user": str(user_api_key_dict),
                })
                raise HTTPException(status_code=403, detail=rule["detail"])

        return data

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        try:
            response_text = response_obj.choices[0].message.content if response_obj else "Unknown"
            total_tokens = response_obj.usage.total_tokens if response_obj else 0
            await self._log_to_splunk({
                "action": "ai_inference",
                "model": kwargs.get("model", "unknown"),
                "user": "ide_user",
                "prompt_preview": str(kwargs.get("messages", []))[:500],
                "response_preview": response_text[:500],
                "total_tokens": total_tokens,
                "duration_ms": (end_time - start_time).total_seconds() * 1000,
                "status": "success"
            })
        except Exception as e:
            print(f"❌ [SPLUNK SUCCESS LOG ERROR]: {e}")

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        try:
            await self._log_to_splunk({
                "action": "ai_inference_failure",
                "model": kwargs.get("model", "unknown"),
                "user": "ide_user",
                "error": str(kwargs.get("exception", "Unknown error")),
                "duration_ms": (end_time - start_time).total_seconds() * 1000,
                "status": "failure"
            })
        except Exception as e:
            print(f"❌ [SPLUNK FAILURE LOG ERROR]: {e}")

    async def _log_to_splunk(self, event_data: dict):
        headers = {
            "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
            "Content-Type": "application/json"
        }
        payload = {"sourcetype": "_json", "index": "casb_gateway", "event": event_data}
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.post(SPLUNK_HEC_URL, json=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    print(f"📡 [SPLUNK] Event logged | HTTP {resp.status}")
        except Exception as e:
            print(f"❌ [SPLUNK SEND ERROR]: {e}")

proxy_handler_instance = SecOpsGateway()
EOF

pass "custom_callbacks.py generated."

###############################################################################
#  STEP 7 — Post-Deploy Smoke Test
###############################################################################
banner "[STEP 7] Post-Deploy Smoke Tests"

echo "┌──────────────────────────────────┬─────────┐"
echo "│  Check                           │ Result  │"
echo "├──────────────────────────────────┼─────────┤"

# 7a. config.yaml exists and is non-empty
if [[ -s config.yaml ]]; then
  echo "│  config.yaml exists & non-empty  │   ✅    │"
else
  echo "│  config.yaml exists & non-empty  │   ❌    │"
fi

# 7b. custom_callbacks.py exists and is non-empty
if [[ -s custom_callbacks.py ]]; then
  echo "│  custom_callbacks.py non-empty   │   ✅    │"
else
  echo "│  custom_callbacks.py non-empty   │   ❌    │"
fi

# 7c. litellm binary is executable
if [[ -x ./venv/bin/litellm ]]; then
  echo "│  ./venv/bin/litellm executable   │   ✅    │"
else
  echo "│  ./venv/bin/litellm executable   │   ❌    │"
fi

# 7d. Splunk container is running
SPLUNK_RUNNING=$(docker inspect -f '{{.State.Running}}' splunk_casb 2>/dev/null || echo "false")
if [[ "$SPLUNK_RUNNING" == "true" ]]; then
  echo "│  splunk_casb container running   │   ✅    │"
else
  echo "│  splunk_casb container running   │   ❌    │"
fi

echo "└──────────────────────────────────┴─────────┘"

###############################################################################
#  STEP 8 — Final Manual Instructions
###############################################################################
banner "[STEP 8] Manual Configuration Steps"

cat << 'INSTRUCTIONS'
╔══════════════════════════════════════════════════════════════════════╗
║          🛡️  Cloud AI CASB — Post-Deployment Checklist 🛡️           ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  1. Open http://localhost:8000 in your browser.                      ║
║     Log in with:                                                     ║
║       • Username: admin                                              ║
║       • Password: (the SPLUNK_PASSWORD value you set in .env)        ║
║                                                                      ║
║  2. In Splunk, go to:                                                ║
║       Settings → Data Inputs → HTTP Event Collector                  ║
║     Create a new HEC token, then update .env:                        ║
║       SPLUNK_HEC_TOKEN=<your-new-token>                              ║
║                                                                      ║
║  3. Open LM Studio, download a model, and start the                  ║
║     Local Server on port 1234 (Developer tab).                       ║
║                                                                      ║
║  4. Re-source the environment file:                                  ║
║       set -a; source .env; set +a                                    ║
║                                                                      ║
║  5. Start the LiteLLM proxy:                                         ║
║       ./venv/bin/litellm --config config.yaml --port 4000            ║
║                                                                      ║
║  6. In VS Code, configure Continue extension to point to:            ║
║       http://localhost:4000/v1                                       ║
║     Set the API key to the value of LITELLM_MASTER_KEY from .env.    ║
║                                                                      ║
║  7. To shut everything down cleanly, run:                            ║
║       bash teardown_cloud_lab.sh                                     ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
INSTRUCTIONS

echo ""
pass "Deployment complete. Follow the steps above to finish configuration."
echo ""
