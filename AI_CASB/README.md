# 🛡️ AI-CASB: AI Cloud Access Security Broker

A self-hosted, open-source **AI Security Gateway** that acts as a transparent proxy between your IDE and local AI models. It enforces **Data Loss Prevention (DLP) guardrails**, logs all inference telemetry to **Splunk**, and provides a real-time **security dashboard** for policy management.

> **TL;DR:** Run local AI models through LM Studio, chat with them via the Continue extension in VS Code, and this gateway blocks sensitive data from reaching the model while logging everything to Splunk for security observability.

---

## 🏗️ Architecture

```
┌─────────────┐      ┌─────────────────────────────────────────────┐
│  VS Code    │      │           AI-CASB Gateway (port 4000)       │
│  Continue   │─────▶│  ┌─────────────┐    ┌──────────────────┐   │
│  Extension  │      │  │  DLP Engine  │───▶│  Splunk Logger    │   │
│             │      │  │  (Guardrails)│    │  (HEC → port 8088)│   │
└─────────────┘      │  └──────┬──────┘    └──────────────────┘   │
                     │         │ PASS                               │
                     │         ▼                                    │
                     │  ┌──────────────┐   ┌──────────────────┐   │
                     │  │  LM Studio   │   │   Ollama         │   │
                     │  │  (port 1234) │   │   (port 11434)   │   │
                     │  │  Local Model │   │   Local Model    │   │
                     │  └──────────────┘   └──────────────────┘   │
                     └─────────────────────────────────────────────┘

┌──────────────────────┐    ┌──────────────────────────┐
│  CASB Dashboard      │    │  Splunk SOC Dashboard    │
│  (port 5001)         │    │  (port 8000)             │
│  Rule Management UI  │    │  Alerts & Telemetry      │
└──────────────────────┘    └──────────────────────────┘
```

## ✨ Features

### 🔒 DLP Guardrails (Data Loss Prevention)
- **7 built-in rules** covering IPs, credentials, credit cards, AWS keys, private keys, PII emails, and SSNs
- **Hot-reload** — edit rules without restarting the proxy
- **Regex-based** — add custom patterns for any sensitive data
- **Per-rule severity** — Critical / High / Medium / Low
- **Enable/disable toggle** — deactivate rules without deleting them

### 📊 Security Observability
- **Splunk Enterprise** integration via HTTP Event Collector (HEC)
- **Dedicated `casb_gateway` index** for isolated security audit
- **Pre-built SOC dashboard** with:
  - DLP block counts and timelines
  - Model usage distribution
  - Inference latency tracking
  - Token consumption metrics
  - Recent alert and inference log tables

### 🎛️ Interactive Dashboard
- **Web-based rule management** at `localhost:5001`
- **Full CRUD** — Create, Read, Update, Delete DLP rules
- **Live regex tester** — validate patterns before deploying
- **Dark cybersecurity theme** with real-time stats

### 🤖 Local Model Support
- **LM Studio** (port 1234) — run any GGUF model locally
- **Ollama** (port 11434) — alternative local inference backend
- **100% offline** — no data ever leaves your machine

---

## 🚀 Quick Start

### Prerequisites
- **Docker** (for Splunk Enterprise)
- **Python 3.10+**
- **LM Studio** ([lmstudio.ai](https://lmstudio.ai)) or **Ollama** ([ollama.com](https://ollama.com))
- **VS Code** with **Continue** extension ([continue.dev](https://continue.dev))

### 1. Clone & Deploy

```bash
git clone https://github.com/Alpha2Admin/Project_Alpha.git
cd Project_Alpha/cloud-sec-gateway
chmod +x deploy_cloud_lab.sh
./deploy_cloud_lab.sh
```

This will:
- ✅ Check prerequisites (Docker, Python, ports)
- ✅ Generate `.env` with placeholder secrets
- ✅ Launch Splunk Enterprise container
- ✅ Create Python venv with dependencies
- ✅ Generate proxy config and DLP callbacks

### 2. Configure Secrets

```bash
nano .env
```

```env
SPLUNK_HEC_TOKEN="your-splunk-hec-token"
SPLUNK_PASSWORD="YourSplunkPassword"
LITELLM_MASTER_KEY="your-secret-proxy-key"
```

### 3. Set Up Splunk HEC

1. Open `http://localhost:8000` → Log in (admin / your password)
2. Go to **Settings → Data Inputs → HTTP Event Collector**
3. Enable HEC globally → Create a new token
4. Create index: **Settings → Indexes → New Index** → name it `casb_gateway`
5. Copy the token to your `.env` file

### 4. Download a Local Model

Open **LM Studio**, search for a lightweight model, and download it:
- **Recommended:** `liquid/lfm2.5-1.2b` (~1 GB, fast on CPU)
- Start the LM Studio **Local Server** (Developer tab → Start Server on port 1234)

### 5. Add Your Model to the Config

Edit `config.yaml` and add your model under the local models section:

```yaml
model_list:
  - model_name: "liquid/lfm2.5-1.2b"
    litellm_params:
      model: "openai/liquid/lfm2.5-1.2b"
      api_base: "http://localhost:1234/v1"
      api_key: "not-needed"
```

> **Tip:** Check your available model IDs at `http://localhost:1234/v1/models`

### 6. Start the Gateway

```bash
./start_casb.sh
```

This launches:
- **LiteLLM Proxy** → `http://localhost:4000`
- **CASB Dashboard** → `http://localhost:5001`
- **Splunk** → `http://localhost:8000`

### 7. Configure Continue Extension in VS Code

Press `Ctrl+Shift+P` → **"Continue: Open Config File"** and set:

```yaml
name: CASB Secured Config
version: 1.0.0
schema: v1
models:
  - name: "🛡️ Local Model"
    provider: openai
    model: liquid/lfm2.5-1.2b
    apiBase: http://localhost:4000/v1
    apiKey: your-litellm-master-key
    roles:
      - chat
      - edit
      - apply
```

> **Key:** Point `apiBase` to `localhost:4000` (the CASB), **not** directly to LM Studio. This ensures all prompts pass through the DLP scanner and Splunk logger.

---

## 📂 Project Structure

```
cloud-sec-gateway/
├── .env.example           # Template for environment variables
├── .gitignore             # Excludes secrets and build artifacts
├── config.yaml            # LiteLLM proxy configuration
├── custom_callbacks.py    # DLP engine + Splunk HEC logger
├── dashboard/
│   └── index.html         # Interactive rule management UI
├── dashboard_server.py    # Flask API for dashboard (port 5001)
├── deploy_cloud_lab.sh    # Automated deployment script
├── dlp_rules.json         # DLP rules database (hot-reloadable)
├── splunk_dashboard.xml   # Pre-built Splunk SOC dashboard
├── start_casb.sh          # One-command startup script
└── teardown_cloud_lab.sh  # Clean teardown script
```

---

## 🛡️ DLP Rules

### Default Rules

| Rule | Severity | Pattern |
|------|----------|---------|
| Internal IPv4 Address | 🟠 High | `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b` |
| Hardcoded Credential | 🔴 Critical | `password\|secret\|api_key = "..."` |
| Credit Card Number | 🔴 Critical | Visa, MC, Amex, Discover formats |
| AWS Access Key | 🟠 High | `AKIA\|ASIA\|AROA` + 16 chars |
| Private Key Block | 🔴 Critical | `-----BEGIN PRIVATE KEY-----` |
| Email Address (PII) | 🟡 Medium | Standard email regex |
| Social Security Number | 🔴 Critical | `XXX-XX-XXXX` format |

### Adding Custom Rules

**Via Dashboard** (recommended):
1. Open `http://localhost:5001`
2. Click "➕ Add New Rule"
3. Fill in name, severity, regex pattern, and violation message
4. Use the built-in regex tester to verify
5. Save — the proxy picks it up automatically (hot-reload)

**Via JSON** (manual):
```json
{
  "id": "rule_custom",
  "name": "GitHub Token",
  "pattern": "ghp_[a-zA-Z0-9]{36}",
  "detail": "CASB Policy Violation: GitHub tokens are not permitted.",
  "enabled": true,
  "severity": "critical"
}
```
Add to `dlp_rules.json` — no restart needed.

---

## 📊 Splunk Dashboard

Import the pre-built SOC dashboard:

1. Open Splunk → **Dashboards → Create New Dashboard**
2. Select **Classic Dashboards**
3. Click **Source** (top left)
4. Paste contents of `splunk_dashboard.xml`
5. Save

The dashboard shows:
- 🚨 DLP block counts (24h)
- 📈 Activity timeline (stacked area chart)
- 🥧 Blocks by rule / severity (pie + bar charts)
- ⏱️ Inference latency over time
- 📋 Recent alerts and inference logs

---

## 🧪 Testing

### Verify DLP Blocking
```bash
# Should be BLOCKED (contains IP address)
curl -s http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"liquid/lfm2.5-1.2b","messages":[{"role":"user","content":"Connect to 192.168.1.50"}]}'

# Should PASS (clean prompt)
curl -s http://localhost:4000/v1/chat/completions \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"liquid/lfm2.5-1.2b","messages":[{"role":"user","content":"What is Python?"}]}'
```

### Verify Splunk Logging
```spl
index=casb_gateway | table _time action model rule severity status
```

---

## ⚠️ Important Notes

- **100% Local** — all inference happens on your machine, no external API calls
- **Never commit `.env`** — it contains your secrets
- **`.env.example`** is the safe template for sharing
- All logs are **stored locally** in Splunk — no data ever leaves your machine
- DLP rules use **hot-reload** — edit `dlp_rules.json` and rules apply immediately
- The proxy enforces a **32,000 character** prompt limit to prevent abuse

---

## 🔧 Teardown

```bash
./teardown_cloud_lab.sh
```

This removes: Splunk container, Python venv, and generated config files.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
