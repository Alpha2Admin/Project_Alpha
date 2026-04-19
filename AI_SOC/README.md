# AI-SOC (Autonomous Security Operations Center) for GenAI Governance

![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Architecture](https://img.shields.io/badge/Architecture-Distributed-green)
![Status](https://img.shields.io/badge/Status-Production_Ready-success)

The **AI-SOC** is a comprehensive, defense-in-depth platform designed to secure, monitor, and govern Generative AI usage across enterprise environments. As AI coding assistants (GitHub Copilot, Cline, Continue) and other LLM tools become ubiquitous, the risk of "Shadow AI," data exfiltration, and prompt injections increases exponentially.

This project establishes a transparent perimeter proxy, identity-aware access controls, real-time threat detection, and automated SOAR orchestration to safely adopt AI without compromising developer velocity.

---

## 🎯 High-Level Architecture

The architecture is built on a distributed SOC model, integrating telemetry from endpoints, gateway enforcement, and centralized response orchestration.

```mermaid
graph TD
    subgraph "Endpoints (Windows Environment)"
        W1[Windows VM 1 - Developer] 
        W2[Windows VM 2 - Standard User]
        Agent[Wazuh Agent + Sysmon]
        Proxy[Security Interceptor]
    end

    subgraph "Security Gateway (AI-CASB)"
        CASB[AI-CASB Engine]
        DLP[DLP / Regex Engine]
        ML[ML Classifier - DeBERTa]
        LDAP[OpenLDAP - RBAC]
        SOAR[Quarantine Manager]
    end

    subgraph "Security Operations Center (SOC)"
        Splunk[(Splunk Enterprise)]
        Wazuh[(Wazuh Manager)]
        IRIS[DFIR-IRIS Case Management]
    end

    W1 & W2 -->|Enforced HTTPS Proxy| CASB
    CASB -->|Audit Logs| Splunk
    CASB -->|Risk Alerts| Wazuh
    Agent -->|Telemetry| Wazuh
    Wazuh -->|Security Alerts| IRIS
    CASB -->|RBAC Query| LDAP
    SOAR -->|Automated Block| CASB
```

---

## 🛡️ Security Coverage & Enforcement

The AI-CASB framework provides a "Defense-in-Depth" strategy for AI usage, ensuring that every prompt and response is analyzed for risk.

### 1. The 8-Layer Inspection Engine
Every prompt passes through 8 detection layers before it reaches the LLM:
1.  **L0: Anti-Evasion**: Normalizes unicode, leetspeak, and homoglyph attacks before analysis.
2.  **L1: Entropy Analysis**: Detects base64-encoded or obfuscated payloads commonly used to exfiltrate data.
3.  **L1.5: ML Classifier**: Uses a locally-hosted **DeBERTa** model to detect semantic prompt injection and jailbreak attempts.
4.  **L2: DLP Regex**: Scans for sensitive patterns such as AWS keys, database credentials, and PII.

![DLP Rules Configuration](./Proofs/AI_CASB_DashBoard/DLP_RULES.png)

### 2. Zero Trust Identity (RBAC)
Integration with **OpenLDAP** ensures real-time identity verification.
*   **Developers**: Allowed to use technical/administrative prompts (monitored).
*   **Standard Users**: Restricted from administrative or sensitive system prompts (blocked).
*   **Auto-Quarantine**: Users exceeding risk thresholds are automatically blocked from all AI services. Analysts can manage unblocking directly from the AI-CASB Command Center.

![Blocked User View](./Proofs/AI_CASB_DashBoard/Blocked%20User.png)

### 3. Wazuh XDR: Shadow AI Detection
Custom Wazuh rules monitor for **Shadow AI** usage—the unauthorized use of non-sanctioned AI services. 
*   **Sysmon Integration (Rule 100200)**: The Wazuh agent monitors DNS resolutions (Event ID 22) and network connections to unauthorized AI domains (e.g., `chat.openai.com`, `claude.ai`).
*   If a developer bypasses the proxy, Wazuh catches it at the endpoint layer.

![Shadow AI Alert in IRIS](./Proofs/Iris/ShadowAI/Alert.png)

### 4. Splunk: Behavioral Detection Logic
All CASB traffic is ingested into Splunk, where complex detection logic aggregates events over 5-15 minute windows:
*   **Brute Force Detection**: Rapid injection attempts.
*   **Probe-to-Strike**: Reconnaissance followed by attack.
*   **Slow Exfiltration**: Sustained low-level data probing.

![Splunk Monitoring Dashboard](./Proofs/Splunk_Dashboard/Logs_Monitored.png)

---

## ⚡ Automated Incident Response (SOAR)

### DFIR-IRIS Case Management
Critical alerts from Wazuh and Splunk automatically generate enriched cases in DFIR-IRIS.
*   **MITRE Mapping**: Every alert is automatically mapped to **MITRE ATT&CK** and **MITRE ATLAS** techniques.
*   **Deep Links**: Alerts contain dynamic links back to **Splunk** (user history) and **Wazuh** (endpoint telemetry).

![User Quarantined Alert in IRIS](./Proofs/Iris/User%20Quarantined/Pasted%20image.png)

### AI-CASB Command Center Dashboard
A custom single pane of glass for SOC analysts to monitor the real-time threat landscape and active MITRE coverage.

![Dashboard MITRE Mapping](./Proofs/AI_CASB_DashBoard/MitreMapping.png)

---

## 📂 Repository Structure

| Component | Description |
| :--- | :--- |
| `cloud-sec-gateway/` | The core Python-based AI-CASB proxy. Contains the ML classifiers, DLP engine, risk scoring, and SIEM/SOAR integration scripts. |
| `ansible/` | Enterprise deployment playbooks. Pushes proxy configurations, root CA certificates, and Wazuh agents to Windows endpoints. |
| `deployment/` | Shell scripts and Docker Compose files for spinning up OpenLDAP, networking, and configuration baselines. |
| `dashboard/` | Command Center UI for SOC analysts to monitor active quarantines, view intercepted prompts, and manage gateway rules. |
| `wazuh-docker/` | Custom Wazuh configurations, including specific decoders and behavioral threshold rules for LLM threat detection. |
| `Proofs/` | Visual documentation and incident response screenshot examples. |

---

## 🚀 Enterprise Deployment Guide

Deploying the AI-SOC requires a distributed architecture. The following runbook outlines the deployment phases across the 6-node topology.

### Prerequisites
*   **Linux Environment** (Ubuntu 22.04+ recommended) for the Gateway and SIEM components.
*   **Python 3.10+** with `pip` and `venv`.
*   **Docker & Docker Compose** for LDAP and XDR components.
*   **Ansible Control Node** for endpoint configuration.

### Phase 1: Identity & Telemetry Foundation
1. **Deploy OpenLDAP (Identity Layer):**
   ```bash
   cd deployment/
   bash ldap_setup_2users.sh
   docker-compose -f docker-compose-ldap.yml up -d
   ```
2. **Configure Splunk (Telemetry):**
   - Navigate to Settings > Data Inputs > HTTP Event Collector.
   - Create a new token for the `casb_gateway` index. Save this token for Phase 2.
3. **Deploy Wazuh XDR:**
   - Import the custom decoders and rules located at the repository root (`wazuh_casb_decoder.xml` and `wazuh_casb_rules.xml`).
   - Push the Sysmon configuration (`deployment/sysmon_shadow_ai.xml`) to your endpoints.

### Phase 2: Deploying the AI-CASB Inspection Engine
1. **Initialize the Environment:**
   ```bash
   cd cloud-sec-gateway/
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. **Configure Secrets & Routing:**
   - Copy `.env.example` to `.env`.
   - Update `SPLUNK_HEC_TOKEN`, `LDAP_ADMIN_PASSWORD`, and `LITELLM_MASTER_KEY` with your production values.
3. **Start the Proxy Services:**
   ```bash
   ./start_casb.sh
   ```

### Phase 3: Endpoint Hooking (Enforcement)
1. **Retrieve the CA Certificate:**
   Extract `mitmproxy-ca-cert.pem` generated during Phase 2.
2. **Automated Enforcement (Ansible):**
   ```bash
   cd ansible/
   ansible-playbook -i inventory.ini deploy_windows_endpoint.yml
   ```

### Phase 4: SOAR & Incident Response
*   Launch the SOC Command Center by navigating to `cloud-sec-gateway/` and running:
    ```bash
    python3 dashboard_server.py
    ```
*   Access the dashboard at `http://<GATEWAY_IP>:5000`.

---

## 🔒 Security & Privacy Notice
This repository is a sanitized version of the internal project. All proprietary data, access tokens, internal IPs, and fine-tuned model weights have been removed or replaced with `REDACTED` placeholders for public release. 
