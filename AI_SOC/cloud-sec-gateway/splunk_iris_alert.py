import requests
import json
import os
import urllib3

# Suppress insecure request warnings for self-signed SOC certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Configuration ---
IRIS_URL = os.getenv("IRIS_URL", "https://localhost:443/api/v1/alerts")

# CRITICAL: This was previously hardcoded. Now uses environment variable.
IRIS_APIKEY = os.getenv("IRIS_API_KEY", "REPLACE_ME_IRIS_API_KEY")

def send_to_iris(alert_data):
    """
    Sends a formatted alert to Splunk IRIS.
    """
    if not IRIS_APIKEY or IRIS_APIKEY == "REPLACE_ME_IRIS_API_KEY":
        print("⚠️ [IRIS] WARNING: IRIS_API_KEY not set. Alert will not be escalated.")
        return

    headers = {
        "Authorization": f"Bearer {IRIS_APIKEY}",
        "Content-Type": "application/json"
    }

    payload = {
        "title": f"CASB Violation: {alert_data.get('rule', 'Unknown Violation')}",
        "description": alert_data.get("detail", "No details provided."),
        "severity": alert_data.get("severity", "medium").upper(),
        "source": "AI-SOC-Infrastructure",
        "tags": ["AI_SECURITY", "SOC", "INFRA"],
    }

    try:
        response = requests.post(
            IRIS_URL,
            data=json.dumps(payload),
            headers=headers,
            verify=False,
            timeout=10
        )
        if response.status_code == 201:
            print(f"✅ [IRIS] Alert successfully escalated to SOC IRIS")
        else:
            print(f"❌ [IRIS] Failed to send alert: {response.status_code}")
    except Exception as e:
        print(f"❌ [IRIS] Connection Error: {e}")
