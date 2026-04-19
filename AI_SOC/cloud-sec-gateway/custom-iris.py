#!/usr/bin/env python3
"""
Wazuh → DFIR-IRIS Integration Script
Forwards AI-CASB behavioral alerts from Wazuh to DFIR-IRIS case management.

Placed at: /var/ossec/integrations/custom-iris.py
Permissions: chown root:wazuh, chmod 750
"""

import json
import sys
import os
import urllib.request
import urllib.error
import ssl
import datetime

# ── Configuration ─────────────────────────────────────────────────────────────
IRIS_URL    = os.getenv("IRIS_URL",    "https://192.168.100.40")
IRIS_APIKEY = os.getenv("IRIS_APIKEY", "REDACTED_IRIS_APIKEY")
CUSTOMER_ID = int(os.getenv("IRIS_CUSTOMER_ID", "1"))

# Map Wazuh rule level → IRIS severity_id
# IRIS severity IDs: 1=Informational, 2=Low, 3=Medium, 4=High, 5=Critical
LEVEL_TO_SEVERITY = {
    range(0, 4):   (2, "Low"),
    range(4, 7):   (2, "Low"),
    range(7, 10):  (3, "Medium"),
    range(10, 13): (4, "High"),
    range(13, 20): (5, "Critical"),
}

def get_severity(level: int):
    for r, (sid, sname) in LEVEL_TO_SEVERITY.items():
        if level in r:
            return sid, sname
    return 3, "Medium"


def send_to_iris(alert_json: dict):
    rule        = alert_json.get("rule", {})
    rule_level  = rule.get("level", 0)
    rule_desc   = rule.get("description", "Unknown Wazuh Alert")
    rule_id     = rule.get("id", "0")
    timestamp   = alert_json.get("timestamp", datetime.datetime.utcnow().isoformat())
    agent       = alert_json.get("agent", {}).get("name", "wazuh-manager")
    data        = alert_json.get("data", {})

    # Extract CASB-specific fields from the alert data
    prompt      = data.get("prompt_preview", data.get("prompt", "N/A"))
    user_id     = data.get("user", data.get("user_id", "unknown"))
    casb_rule   = data.get("rule", data.get("casb_rule", "N/A"))
    severity    = data.get("severity", "unknown")
    action      = data.get("action", "unknown")
    
    agent_id    = alert_json.get("agent", {}).get("id", "000")

    sev_id, sev_name = get_severity(rule_level)
    
    # Generate Splunk Deep Link for the specific user
    splunk_url = f"http://192.168.100.20:8000/en-US/app/search/search?q=search%20index%3Dcasb_gateway%20user%3D%22{user_id}%22"
    
    # Generate dynamic Wazuh Source Link (Shadow AI points to specific agent dashboard)
    if str(rule_id) == "100200" or "Shadow AI" in rule_desc:
        source_link = f"https://192.168.100.30/app/wazuh#/agents?agent={agent_id}"
    else:
        source_link = "https://192.168.100.30"

    title = f"AI-CASB: {rule_desc}"
    description = (
        f"**Wazuh Rule ID:** {rule_id} (Level {rule_level})\n"
        f"**Agent:** {agent}\n"
        f"**Timestamp:** {timestamp}\n\n"
        f"---\n\n"
        f"**CASB Action:** `{action}`\n"
        f"**CASB Severity:** `{severity.upper()}`\n"
        f"**DLP Rule Triggered:** `{casb_rule}`\n"
        f"**User ID:** `{user_id}`\n"
        f"**Prompt Preview:** `{prompt}`\n\n"
        f"---\n\n"
        f"**Investigation Links:**\n"
        f"- [View user history in Splunk]({splunk_url})\n"
        f"- [View Endpoint in Wazuh]({source_link})"
    )

    payload = {
        "alert_title":          title,
        "alert_description":    description,
        "alert_source":         "Wazuh-AI-CASB",
        "alert_source_ref":     f"wazuh-rule-{rule_id}",
        "alert_source_link":    source_link,
        "alert_severity_id":    sev_id,
        "alert_status_id":      1,          # 1 = New
        "alert_customer_id":    CUSTOMER_ID,
        "alert_source_event_time": timestamp,
        "alert_tags":           f"wazuh,ai-casb,{severity},{action}",
        "alert_source_content": alert_json,
    }

    body = json.dumps(payload).encode("utf-8")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE

    req = urllib.request.Request(
        url     = f"{IRIS_URL}/alerts/add",
        data    = body,
        headers = {
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {IRIS_APIKEY}",
        },
        method = "POST",
    )

    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            resp_body = resp.read().decode("utf-8")
            resp_json = json.loads(resp_body)
            if resp_json.get("status") == "success":
                print(f"[IRIS] Alert created: {title}")
            else:
                print(f"[IRIS] Unexpected response: {resp_body}", file=sys.stderr)
    except urllib.error.HTTPError as e:
        print(f"[IRIS] HTTP {e.code}: {e.read().decode()}", file=sys.stderr)
    except Exception as e:
        print(f"[IRIS] Error: {e}", file=sys.stderr)


def main():
    # Wazuh passes the alert file path as the first argument
    if len(sys.argv) < 2:
        print("[IRIS] No alert file path provided", file=sys.stderr)
        sys.exit(1)

    alert_file = sys.argv[1]

    try:
        with open(alert_file, "r") as f:
            alert_json = json.load(f)
    except Exception as e:
        print(f"[IRIS] Failed to read alert file: {e}", file=sys.stderr)
        sys.exit(1)

    send_to_iris(alert_json)


if __name__ == "__main__":
    main()
