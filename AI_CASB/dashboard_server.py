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


if __name__ == "__main__":
    os.makedirs("dashboard", exist_ok=True)
    print("🛡️  CASB Dashboard running at http://localhost:5001")
    app.run(host="0.0.0.0", port=5001, debug=False)
