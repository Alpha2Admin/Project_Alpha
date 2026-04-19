#!/usr/bin/env python3
"""
AI-CASB → DFIR-IRIS Alert Bridge
Deployed to: /opt/splunk/etc/apps/search/bin/casb_iris_alert.py

Splunk custom alert action arguments:
  $1 = number of events
  $2 = search name
  $3 = ...
  $4 = search name (again, Splunk convention)
  $5 = trigger reason
  $6 = search URI
  $7 = deprecated
  $8 = path to results file (CSV/gzip)
"""

import sys, os, csv, gzip, json, ssl, urllib.request, urllib.error
import datetime, logging

IRIS_URL    = os.getenv("IRIS_URL",    "https://192.168.100.40")
IRIS_APIKEY = os.getenv("IRIS_APIKEY", "REDACTED_IRIS_APIKEY")
CUSTOMER_ID = int(os.getenv("IRIS_CUSTOMER_ID", "1"))
SPLUNK_URL  = "http://192.168.100.20:8000"
WAZUH_URL   = "https://192.168.100.30"
LOG_FILE    = "/tmp/casb_iris_alert.log"

logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format="%(asctime)s [CASB-IRIS] %(levelname)s: %(message)s")
log = logging.getLogger("casb_iris_alert")

# ── MITRE ATT&CK + ATLAS Taxonomy ─────────────────────────────────────────────
# Each technique: (id, tactic, name, url)
MITRE_ATTACK = {
    "T1190": ("T1190", "initial-access",      "Exploit Public-Facing Application",
               "https://attack.mitre.org/techniques/T1190/"),
    "T1059": ("T1059", "execution",           "Command and Scripting Interpreter",
               "https://attack.mitre.org/techniques/T1059/"),
    "T1078": ("T1078", "initial-access",      "Valid Accounts",
               "https://attack.mitre.org/techniques/T1078/"),
    "T1048": ("T1048", "exfiltration",        "Exfiltration Over Alternative Protocol",
               "https://attack.mitre.org/techniques/T1048/"),
    "T1530": ("T1530", "collection",          "Data from Cloud Storage Object",
               "https://attack.mitre.org/techniques/T1530/"),
    "T1595": ("T1595", "reconnaissance",      "Active Scanning",
               "https://attack.mitre.org/techniques/T1595/"),
    "T1046": ("T1046", "discovery",           "Network Service Discovery",
               "https://attack.mitre.org/techniques/T1046/"),
    "T1213": ("T1213", "collection",          "Data from Information Repositories",
               "https://attack.mitre.org/techniques/T1213/"),
}

MITRE_ATLAS = {
    "AML.T0051": ("AML.T0051", "ml-attack-staging", "LLM Prompt Injection",
                  "https://atlas.mitre.org/techniques/AML.T0051"),
    "AML.T0054": ("AML.T0054", "impact",             "LLM Jailbreak",
                  "https://atlas.mitre.org/techniques/AML.T0054"),
    "AML.T0040": ("AML.T0040", "ml-attack-staging",  "ML Inference API Access",
                  "https://atlas.mitre.org/techniques/AML.T0040"),
    "AML.T0048": ("AML.T0048", "exfiltration",       "Exfiltration via ML Inference API",
                  "https://atlas.mitre.org/techniques/AML.T0048"),
    "AML.T0048.002": ("AML.T0048.002", "exfiltration", "Exfiltration via ML Inference API: Batch Queries",
                      "https://atlas.mitre.org/techniques/AML.T0048/002"),
    "AML.T0043": ("AML.T0043", "ml-attack-staging",  "Craft Adversarial Data",
                  "https://atlas.mitre.org/techniques/AML.T0043"),
    "AML.T0046": ("AML.T0046", "impact",             "Jailbreak - Multi-Turn",
                  "https://atlas.mitre.org/techniques/AML.T0046"),
}

# ── Detection Profiles ─────────────────────────────────────────────────────────
DETECTION_PROFILES = {
    "CASB_Brute_Force_Detection": {
        "title_prefix":  "Brute Force Prompt Injection",
        "severity_id":   4,
        "severity_name": "High",
        "tactic":        "Initial Access → Execution",
        "mitre_attack":  ["T1190", "T1059"],
        "mitre_atlas":   ["AML.T0051", "AML.T0054"],
        "tags":          ["ai-casb", "brute-force", "prompt-injection", "wazuh", "T1190", "T1059", "AML.T0051", "AML.T0054"],
        "description_tpl": (
            "## Behavioral Pattern: Brute Force Prompt Probing\n\n"
            "| Field | Value |\n"
            "|---|---|\n"
            "| **User** | `{user}` |\n"
            "| **Blocked Prompts** | {block_count} within 5 minutes |\n"
            "| **Detection Layer** | L1.5 Semantic + L2 DLP |\n"
            "| **CASB Action** | Blocked (403) |\n"
            "| **Behavioral Signal** | Automated or manual iteration on injection variants |\n\n"
            "---\n\n"
            "## MITRE ATT&CK Mapping\n\n"
            "| Framework | ID | Tactic | Technique |\n"
            "|---|---|---|---|\n"
            "| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/) | Initial Access | Exploit Public-Facing Application |\n"
            "| ATT&CK | [T1059](https://attack.mitre.org/techniques/T1059/) | Execution | Command and Scripting Interpreter |\n"
            "| ATLAS  | [AML.T0051](https://atlas.mitre.org/techniques/AML.T0051) | ML Attack Staging | LLM Prompt Injection |\n"
            "| ATLAS  | [AML.T0054](https://atlas.mitre.org/techniques/AML.T0054) | Impact | LLM Jailbreak |\n\n"
            "---\n\n"
            "## Investigation Links\n\n"
            "- 🔍 [Splunk: User Prompt History](http://192.168.100.20:8000/en-US/app/search/search?"
            "q=search%20index%3Dcasb_gateway%20user%3D%22{user}%22%20%7C%20table%20_time%2Caction%2Crule%2Cseverity%2Cprompt_preview%20%7C%20sort%20-_time)\n"
            "- 🛡️ [Wazuh: Endpoint Alerts for {user}](https://192.168.100.30/app/data-explorer/discover#?"
            "_a=(discover:(columns:!(_source),index:'wazuh-alerts-*',query:(language:kuery,"
            "query:'data.user:\"{user}\"'))))\n"
            "- 📊 [Wazuh: Risk Score Dashboard](https://192.168.100.30/app/dashboards)\n"
        ),
    },
    "CASB_Probe_Strike_Detection": {
        "title_prefix":  "Probe-to-Strike Attack Pattern",
        "severity_id":   4,
        "severity_name": "High",
        "tactic":        "Reconnaissance → Initial Access",
        "mitre_attack":  ["T1190", "T1078"],
        "mitre_atlas":   ["AML.T0051", "AML.T0040"],
        "tags":          ["ai-casb", "probe-strike", "reconnaissance", "behavioral", "wazuh", "T1190", "T1078", "AML.T0051", "AML.T0040"],
        "description_tpl": (
            "## Behavioral Pattern: Reconnaissance → Attack\n\n"
            "| Field | Value |\n"
            "|---|---|\n"
            "| **User** | `{user}` |\n"
            "| **Flagged Probes** | {flags} (allowed, just-below-threshold) |\n"
            "| **Blocked Attacks** | {blocks} within 10 minutes |\n"
            "| **Pattern** | Adversary testing system boundaries before escalating |\n\n"
            "---\n\n"
            "## MITRE ATT&CK Mapping\n\n"
            "| Framework | ID | Tactic | Technique |\n"
            "|---|---|---|---|\n"
            "| ATT&CK | [T1190](https://attack.mitre.org/techniques/T1190/) | Initial Access | Exploit Public-Facing Application |\n"
            "| ATT&CK | [T1078](https://attack.mitre.org/techniques/T1078/) | Initial Access | Valid Accounts |\n"
            "| ATLAS  | [AML.T0051](https://atlas.mitre.org/techniques/AML.T0051) | ML Attack Staging | LLM Prompt Injection |\n"
            "| ATLAS  | [AML.T0040](https://atlas.mitre.org/techniques/AML.T0040) | ML Attack Staging | ML Inference API Access |\n\n"
            "---\n\n"
            "## Investigation Links\n\n"
            "- 🔍 [Splunk: User Prompt History](http://192.168.100.20:8000/en-US/app/search/search?"
            "q=search%20index%3Dcasb_gateway%20user%3D%22{user}%22%20%7C%20table%20_time%2Caction%2Crule%2Cseverity%2Cprompt_preview%20%7C%20sort%20-_time)\n"
            "- 🛡️ [Wazuh: Endpoint Alerts for {user}](https://192.168.100.30/app/data-explorer/discover#?"
            "_a=(discover:(columns:!(_source),index:'wazuh-alerts-*',query:(language:kuery,"
            "query:'data.user:\"{user}\"'))))\n"
        ),
    },
    "CASB_Slow_Exfil_Detection": {
        "title_prefix":  "Slow Data Exfiltration via AI",
        "severity_id":   3,
        "severity_name": "Medium",
        "tactic":        "Collection → Exfiltration",
        "mitre_attack":  ["T1048", "T1530"],
        "mitre_atlas":   ["AML.T0048.002", "AML.T0043"],
        "tags":          ["ai-casb", "slow-exfil", "data-leak", "dlp", "wazuh", "T1048", "T1530", "AML.T0048", "AML.T0043"],
        "description_tpl": (
            "## Behavioral Pattern: Sustained Low-Level Data Probing\n\n"
            "| Field | Value |\n"
            "|---|---|\n"
            "| **User** | `{user}` |\n"
            "| **Flagged Prompts** | {flag_count} within 15 minutes (no blocks) |\n"
            "| **Pattern** | Multiple small just-below-threshold prompts |\n"
            "| **Risk** | Slow exfiltration of sensitive data via AI responses |\n\n"
            "---\n\n"
            "## MITRE ATT&CK Mapping\n\n"
            "| Framework | ID | Tactic | Technique |\n"
            "|---|---|---|---|\n"
            "| ATT&CK | [T1048](https://attack.mitre.org/techniques/T1048/) | Exfiltration | Exfiltration Over Alternative Protocol |\n"
            "| ATT&CK | [T1530](https://attack.mitre.org/techniques/T1530/) | Collection | Data from Cloud Storage Object |\n"
            "| ATLAS  | [AML.T0048.002](https://atlas.mitre.org/techniques/AML.T0048/002) | Exfiltration | Exfiltration via ML Inference API: Batch Queries |\n"
            "| ATLAS  | [AML.T0043](https://atlas.mitre.org/techniques/AML.T0043) | ML Attack Staging | Craft Adversarial Data |\n\n"
            "---\n\n"
            "## Investigation Links\n\n"
            "- 🔍 [Splunk: User Prompt History](http://192.168.100.20:8000/en-US/app/search/search?"
            "q=search%20index%3Dcasb_gateway%20user%3D%22{user}%22%20%7C%20table%20_time%2Caction%2Crule%2Cseverity%2Cprompt_preview%20%7C%20sort%20-_time)\n"
            "- 🛡️ [Wazuh: Endpoint Alerts for {user}](https://192.168.100.30/app/data-explorer/discover#?"
            "_a=(discover:(columns:!(_source),index:'wazuh-alerts-*',query:(language:kuery,"
            "query:'data.user:\"{user}\"'))))\n"
        ),
    },
}


def build_iocs(profile: dict, user: str) -> list:
    """Build structured IOC list including MITRE technique links."""
    iocs = []
    for tid in profile["mitre_attack"]:
        meta = MITRE_ATTACK.get(tid)
        if meta:
            iocs.append({
                "ioc_value":       meta[0],
                "ioc_description": f"[ATT&CK {meta[1].upper()}] {meta[2]}",
                "ioc_type_id":     14,   # 14 = url in IRIS default IOC types
                "ioc_tlp_id":      1,    # TLP:WHITE
                "ioc_tags":        f"mitre-attack,{meta[1]},{tid}",
            })
    for tid in profile["mitre_atlas"]:
        meta = MITRE_ATLAS.get(tid)
        if meta:
            iocs.append({
                "ioc_value":       meta[3],
                "ioc_description": f"[ATLAS {meta[1].upper()}] {meta[2]} ({meta[0]})",
                "ioc_type_id":     14,
                "ioc_tlp_id":      1,
                "ioc_tags":        f"mitre-atlas,{meta[1]},{tid}",
            })
    # User identity IOC
    iocs.append({
        "ioc_value":       f"user:{user}",
        "ioc_description": f"Offending CASB user identity: {user}",
        "ioc_type_id":     15,   # 15 = username
        "ioc_tlp_id":      2,    # TLP:GREEN
        "ioc_tags":        "casb,identity,user",
    })
    return iocs


def send_to_iris(payload: dict) -> bool:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    body = json.dumps(payload).encode("utf-8")
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
            rj = json.loads(resp.read().decode())
            if rj.get("status") == "success":
                aid = rj.get("data", {}).get("alert_id", "?")
                log.info(f"IRIS alert #{aid}: {payload['alert_title']}")
                return True
            log.error(f"IRIS unexpected: {rj}")
    except urllib.error.HTTPError as e:
        log.error(f"IRIS HTTP {e.code}: {e.read().decode()}")
    except Exception as e:
        log.error(f"IRIS error: {e}")
    return False


def read_results(results_file: str) -> list:
    rows = []
    try:
        f = gzip.open(results_file, "rt") if results_file.endswith(".gz") else open(results_file)
        rows = list(csv.DictReader(f))
        f.close()
    except Exception as e:
        log.error(f"read_results: {e}")
    return rows


def main():
    if len(sys.argv) < 9:
        log.error(f"Too few args: {len(sys.argv)}")
        sys.exit(1)

    search_name  = sys.argv[4]
    results_file = sys.argv[8]
    now = datetime.datetime.utcnow().isoformat() + "Z"

    profile = DETECTION_PROFILES.get(search_name)
    if not profile:
        log.warning(f"Unknown saved search '{search_name}'")
        sys.exit(0)

    rows = read_results(results_file)
    if not rows:
        log.warning("No result rows.")
        sys.exit(0)

    for row in rows:
        user = row.get("user", "unknown_user")

        desc = profile["description_tpl"].format(
            user=user,
            block_count=row.get("block_count", row.get("blocks", "?")),
            flag_count=row.get("flag_count", row.get("flags", "?")),
            blocks=row.get("blocks", "?"),
            flags=row.get("flags", "?"),
        )

        # Build enriched source content with Wazuh + Splunk correlation data
        source_content = {
            **row,
            "casb_version": "5.0",
            "wazuh_query": f"data.user:\"{user}\"",
            "wazuh_dashboard": f"{WAZUH_URL}/app/data-explorer/discover",
            "splunk_search": f"index=casb_gateway user=\"{user}\" | table _time,action,rule,severity,prompt_preview | sort -_time",
            "splunk_dashboard": f"{SPLUNK_URL}/en-US/app/search/search",
            "mitre_attack_ids": profile["mitre_attack"],
            "mitre_atlas_ids":  profile["mitre_atlas"],
            "detection_tactic": profile["tactic"],
        }

        payload = {
            "alert_title":             f"{profile['title_prefix']}: User '{user}'",
            "alert_description":       desc,
            "alert_source":            "Wazuh-AI-CASB",
            "alert_source_ref":        f"splunk-{search_name}-{user}-{now}",
            "alert_source_link":       f"{SPLUNK_URL}/en-US/app/search/search?q=search%20index%3Dcasb_gateway%20user%3D%22{user}%22",
            "alert_severity_id":       profile["severity_id"],
            "alert_status_id":         2,
            "alert_customer_id":       CUSTOMER_ID,
            "alert_source_event_time": now,
            "alert_tags":              ",".join(profile["tags"]),
            "alert_source_content":    source_content,
            "alert_iocs":              build_iocs(profile, user),
        }

        ok = send_to_iris(payload)
        status = "✅" if ok else "❌"
        log.info(f"{status} IRIS alert for '{user}' [{profile['title_prefix']}]")


if __name__ == "__main__":
    main()
