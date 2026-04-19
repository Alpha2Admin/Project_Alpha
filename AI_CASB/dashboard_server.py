#!/usr/bin/env python3
"""
CASB Security Dashboard — Flask API Backend
Serves the dashboard UI and provides REST API for DLP rule management.
Runs on port 5001.
"""

import json
import os
import re
import uuid
from datetime import datetime
from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__, static_folder="dashboard")

RULES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dlp_rules.json")


def load_rules():
    with open(RULES_FILE, "r") as f:
        return json.load(f)


def save_rules(rules):
    with open(RULES_FILE, "w") as f:
        json.dump(rules, f, indent=2)


# ── Serve Dashboard UI ────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("dashboard", "index.html")


# ── Rules API ─────────────────────────────────────────────────────
@app.route("/api/rules", methods=["GET"])
def get_rules():
    return jsonify(load_rules())


@app.route("/api/rules", methods=["POST"])
def create_rule():
    data = request.json
    rules = load_rules()
    new_rule = {
        "id": f"rule_{uuid.uuid4().hex[:8]}",
        "name": data["name"],
        "pattern": data["pattern"],
        "detail": data["detail"],
        "enabled": data.get("enabled", True),
        "severity": data.get("severity", "medium"),
        "created_at": datetime.utcnow().isoformat()
    }
    # Validate regex
    try:
        re.compile(new_rule["pattern"])
    except re.error as e:
        return jsonify({"error": f"Invalid regex pattern: {e}"}), 400
    rules.append(new_rule)
    save_rules(rules)
    return jsonify(new_rule), 201


@app.route("/api/rules/<rule_id>", methods=["PUT"])
def update_rule(rule_id):
    data = request.json
    rules = load_rules()
    for i, rule in enumerate(rules):
        if rule["id"] == rule_id:
            # Validate regex if pattern is changing
            if "pattern" in data:
                try:
                    re.compile(data["pattern"])
                except re.error as e:
                    return jsonify({"error": f"Invalid regex pattern: {e}"}), 400
            rules[i].update(data)
            rules[i]["updated_at"] = datetime.utcnow().isoformat()
            save_rules(rules)
            return jsonify(rules[i])
    return jsonify({"error": "Rule not found"}), 404


@app.route("/api/rules/<rule_id>", methods=["DELETE"])
def delete_rule(rule_id):
    rules = load_rules()
    original_len = len(rules)
    rules = [r for r in rules if r["id"] != rule_id]
    if len(rules) == original_len:
        return jsonify({"error": "Rule not found"}), 404
    save_rules(rules)
    return jsonify({"success": True})


@app.route("/api/rules/<rule_id>/toggle", methods=["POST"])
def toggle_rule(rule_id):
    rules = load_rules()
    for i, rule in enumerate(rules):
        if rule["id"] == rule_id:
            rules[i]["enabled"] = not rules[i].get("enabled", True)
            save_rules(rules)
            return jsonify({"enabled": rules[i]["enabled"]})
    return jsonify({"error": "Rule not found"}), 404


@app.route("/api/rules/test", methods=["POST"])
def test_rule():
    """Test a regex pattern against a sample text."""
    data = request.json
    pattern = data.get("pattern", "")
    sample = data.get("sample", "")
    try:
        match = re.search(pattern, sample)
        return jsonify({"match": bool(match), "matched_text": match.group(0) if match else None})
    except re.error as e:
        return jsonify({"error": f"Invalid regex: {e}"}), 400


# ── v5.0: Compliance & SOAR API ──────────────────────────────────────────────

@app.route("/api/compliance", methods=["GET"])
def get_compliance():
    """Return compliance data: risk users, MITRE coverage, scorecards."""
    try:
        from risk_scoring import get_top_users
        risk_users = get_top_users(10)
    except Exception:
        risk_users = []

    try:
        from quarantine_manager import quarantine
        quarantined = quarantine.get_quarantined_users()
        soar_log = quarantine.get_audit_log(20)
    except Exception:
        quarantined = []
        soar_log = []

    # MITRE ATLAS Coverage Matrix
    mitre_atlas = [
        {"id": "AML.T0051", "name": "LLM Prompt Injection",   "covered": True,  "layer": "L1.5 DeBERTa + L2 DLP"},
        {"id": "AML.T0054", "name": "LLM Jailbreak",           "covered": True,  "layer": "L1.5 Semantic + L0 Normalizer"},
        {"id": "AML.T0040", "name": "ML Model Inference API Access", "covered": True, "layer": "Risk Scoring + SOAR"},
        {"id": "AML.T0043", "name": "Craft Adversarial Data",  "covered": True,  "layer": "L0 Anti-Evasion"},
        {"id": "AML.T0048.002", "name": "Exfiltration via ML Inference API", "covered": True, "layer": "L3 Egress DLP"},
        {"id": "AML.T0042", "name": "Create Proxy ML Model",  "covered": False, "layer": "—"},
        {"id": "AML.T0044", "name": "Full ML Model Access",   "covered": False, "layer": "—"},
        {"id": "AML.T0047", "name": "ML Supply Chain Compromise", "covered": False, "layer": "—"},
    ]

    mitre_attack = [
        {"id": "T1190", "name": "Exploit Public-Facing Application", "covered": True, "layer": "L1.5 + L2"},
        {"id": "T1059", "name": "Command and Scripting Interpreter", "covered": True, "layer": "L1 Entropy + L2 DLP"},
        {"id": "T1078", "name": "Valid Accounts",              "covered": True,  "layer": "User Identity + Risk Scoring"},
        {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "covered": True, "layer": "L3 Egress + Shadow AI"},
        {"id": "T1530", "name": "Data from Cloud Storage",     "covered": True,  "layer": "L3 Egress DLP"},
        {"id": "T1027", "name": "Obfuscated Files or Information", "covered": True, "layer": "L0 Normalizer + L1 Entropy"},
        {"id": "T1140", "name": "Deobfuscate/Decode Files",    "covered": True,  "layer": "L0 Normalizer"},
        {"id": "T1204", "name": "User Execution",              "covered": True,  "layer": "Multi-Turn Tracker"},
        {"id": "T1552", "name": "Unsecured Credentials",       "covered": True,  "layer": "L2 DLP (AWS keys, passwords)"},
    ]

    # Compliance Scorecards
    scorecards = [
        {"framework": "NIST AI RMF",  "score": 85, "details": "Risk scoring ✅ | Behavioral detection ✅ | Model governance ✅ | Incident response ✅"},
        {"framework": "SOC 2",        "score": 90, "details": "Audit logging ✅ | Access control ✅ | Change management ✅ | Incident mgmt ✅"},
        {"framework": "GDPR (AI Act)","score": 75, "details": "PII detection ✅ | Egress redaction ✅ | Data minimization ⚠️ | Transparency ⚠️"},
        {"framework": "OWASP LLM",    "score": 92, "details": "Prompt injection ✅ | Data leakage ✅ | Model DoS ✅ | Supply chain ⚠️"},
    ]

    return jsonify({
        "risk_users": risk_users,
        "quarantined_users": quarantined,
        "soar_log": soar_log,
        "mitre_atlas": mitre_atlas,
        "mitre_attack": mitre_attack,
        "scorecards": scorecards,
    })


@app.route("/api/soar/quarantined", methods=["GET"])
def get_quarantined():
    """List quarantined users."""
    try:
        from quarantine_manager import quarantine
        return jsonify({"quarantined": quarantine.get_quarantined_users()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/soar/unblock/<user_id>", methods=["POST"])
def unblock_user(user_id):
    """Unblock a quarantined user."""
    try:
        from quarantine_manager import quarantine
        was_blocked = quarantine.unblock_user(user_id)
        return jsonify({"success": True, "was_blocked": was_blocked, "user_id": user_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    os.makedirs("dashboard", exist_ok=True)
    print("🛡️  CASB Dashboard running at http://localhost:5001")
    app.run(host="0.0.0.0", port=5001, debug=False)
