#!/usr/bin/env python3
"""
Splunk → DFIR-IRIS Alert Bridge
================================
Called by Splunk's scripted alert action when a behavioral detection fires.
Reads the search results CSV, builds an IRIS alert with MITRE ATT&CK + ATLAS
tags, and POSTs it to the IRIS REST API.

Splunk passes these arguments:
  $0  script name
  $1  number of events returned
  $2  search terms
  $3  fully qualified query string
  $4  name of the saved search
  $5  trigger reason
  $6  browser URL to view results
  $7  deprecated
  $8  path to results file (CSV/gzip)

Deployed to: /opt/splunk/etc/apps/search/bin/casb_iris_alert.py
"""

import sys
import os
import csv
import gzip
import json
import ssl
import urllib.request
import urllib.error
import datetime
import logging

# ── Configuration ─────────────────────────────────────────────────────────────
IRIS_URL    = os.getenv("IRIS_URL",    "https://192.168.100.40")
IRIS_APIKEY = os.getenv("IRIS_APIKEY", "REDACTED_IRIS_KEY")
CUSTOMER_ID = int(os.getenv("IRIS_CUSTOMER_ID", "1"))
LOG_FILE    = "/opt/splunk/var/log/splunk/casb_iris_alert.log"

# ── MITRE Mapping per Detection Pattern ───────────────────────────────────────
DETECTION_PROFILES = {
    "CASB_Brute_Force_Detection": {
        "title_prefix":   "Brute Force Prompt Injection",
        "severity_id":    4,   # High
        "severity_name":  "high",
        "description_tpl": (
            "**Behavioral Pattern: Brute Force Probing**\n\n"
            "User `{user}` triggered **{block_count} blocked prompts** within 5 minutes.\n"
            "This indicates automated or manual iteration on prompt injection variants.\n\n"
            "---\n\n"
            "**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application), T1059 (Command Injection)\n"
            "**MITRE ATLAS:** AML.T0051 (LLM Prompt Injection), AML.T0054 (LLM Jailbreak)\n"
        ),
        "mitre_attack": ["T1190", "T1059"],
        "mitre_atlas":  ["AML.T0051", "AML.T0054"],
        "tags": "brute-force,prompt-injection,behavioral",
    },
    "CASB_Probe_Strike_Detection": {
        "title_prefix":   "Probe-to-Strike Attack Pattern",
        "severity_id":    4,   # High
        "severity_name":  "high",
        "description_tpl": (
            "**Behavioral Pattern: Reconnaissance → Attack**\n\n"
            "User `{user}` sent **{flags} flagged (allowed) probes** followed by "
            "**{blocks} blocked attack(s)** within 10 minutes.\n"
            "This pattern indicates an adversary testing the system boundaries before escalating.\n\n"
            "---\n\n"
            "**MITRE ATT&CK:** T1190 (Exploit Public-Facing App), T1078 (Valid Accounts)\n"
            "**MITRE ATLAS:** AML.T0051 (LLM Prompt Injection), AML.T0040 (ML Inference API Access)\n"
        ),
        "mitre_attack": ["T1190", "T1078"],
        "mitre_atlas":  ["AML.T0051", "AML.T0040"],
        "tags": "probe-strike,reconnaissance,behavioral",
    },
    "CASB_Slow_Exfil_Detection": {
        "title_prefix":   "Slow Data Exfiltration via AI",
        "severity_id":    3,   # Medium
        "severity_name":  "medium",
        "description_tpl": (
            "**Behavioral Pattern: Sustained Low-Level Probing**\n\n"
            "User `{user}` triggered **{flag_count} flagged (allowed) prompts** within 15 minutes "
            "without any blocks.\n"
            "This may indicate data exfiltration via multiple small, just-below-threshold prompts.\n\n"
            "---\n\n"
            "**MITRE ATT&CK:** T1048 (Exfiltration Over Alternative Protocol), T1530 (Data from Cloud Storage)\n"
            "**MITRE ATLAS:** AML.T0048.002 (Exfiltration via ML Inference API), AML.T0043 (Craft Adversarial Data)\n"
        ),
        "mitre_attack": ["T1048", "T1530"],
        "mitre_atlas":  ["AML.T0048.002", "AML.T0043"],
        "tags": "slow-exfil,data-leak,behavioral",
    },
}

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [CASB-IRIS] %(levelname)s: %(message)s",
)
log = logging.getLogger("casb_iris_alert")


def read_results(results_file: str) -> list[dict]:
    """Read Splunk search results from CSV (may be gzip-compressed)."""
    rows = []
    try:
        if results_file.endswith(".gz"):
            f = gzip.open(results_file, "rt")
        else:
            f = open(results_file, "r")
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
        f.close()
    except Exception as e:
        log.error(f"Failed to read results file: {e}")
    return rows


def send_to_iris(payload: dict) -> bool:
    """POST an alert to DFIR-IRIS."""
    body = json.dumps(payload).encode("utf-8")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    req = urllib.request.Request(
        url=f"{IRIS_URL}/alerts/add",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {IRIS_APIKEY}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            resp_body = resp.read().decode("utf-8")
            resp_json = json.loads(resp_body)
            if resp_json.get("status") == "success":
                log.info(f"IRIS alert created: {payload['alert_title']}")
                return True
            else:
                log.error(f"IRIS unexpected response: {resp_body}")
    except urllib.error.HTTPError as e:
        log.error(f"IRIS HTTP {e.code}: {e.read().decode()}")
    except Exception as e:
        log.error(f"IRIS connection error: {e}")
    return False


def main():
    if len(sys.argv) < 9:
        log.error(f"Not enough arguments (got {len(sys.argv)}). Expected Splunk alert args.")
        sys.exit(1)

    num_events   = sys.argv[1]
    search_name  = sys.argv[4]
    trigger_reason = sys.argv[5]
    results_file = sys.argv[8]

    log.info(f"Alert fired: '{search_name}' | events={num_events} | reason={trigger_reason}")

    # Look up detection profile
    profile = DETECTION_PROFILES.get(search_name)
    if not profile:
        log.warning(f"Unknown saved search '{search_name}', skipping.")
        sys.exit(0)

    # Read the results
    rows = read_results(results_file)
    if not rows:
        log.warning("No result rows to process.")
        sys.exit(0)

    now = datetime.datetime.utcnow().isoformat() + "Z"

    # Create one IRIS alert per user in the results
    for row in rows:
        user = row.get("user", "unknown_user")

        # Build description from template
        desc = profile["description_tpl"].format(
            user=user,
            block_count=row.get("block_count", row.get("blocks", "?")),
            flag_count=row.get("flag_count", row.get("flags", "?")),
            blocks=row.get("blocks", "?"),
            flags=row.get("flags", "?"),
        )

        # Build MITRE tag string
        mitre_str = ", ".join(profile["mitre_attack"] + profile["mitre_atlas"])

        payload = {
            "alert_title":          f"{profile['title_prefix']}: User '{user}'",
            "alert_description":    desc,
            "alert_source":         "Splunk-AI-CASB",
            "alert_source_ref":     f"splunk-{search_name}-{user}-{now}",
            "alert_source_link":    "https://192.168.100.20:8000",
            "alert_severity_id":    profile["severity_id"],
            "alert_status_id":      2,  # 2 = New (unread)
            "alert_customer_id":    CUSTOMER_ID,
            "alert_source_event_time": now,
            "alert_tags":           f"ai-casb,{profile['tags']},{mitre_str}",
            "alert_source_content": row,
        }

        success = send_to_iris(payload)
        if success:
            log.info(f"✅ Created IRIS alert for user '{user}' [{profile['title_prefix']}]")
        else:
            log.error(f"❌ Failed to create IRIS alert for user '{user}'")


if __name__ == "__main__":
    main()
