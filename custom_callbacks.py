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

# --- Dynamic DLP Rules (hot-reload from JSON) ---
RULES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dlp_rules.json")
_rules_cache = []
_rules_mtime = 0

def load_dlp_rules():
    """Load DLP rules from JSON file. Hot-reloads when file changes."""
    global _rules_cache, _rules_mtime
    try:
        current_mtime = os.path.getmtime(RULES_FILE)
        if current_mtime != _rules_mtime:
            with open(RULES_FILE, "r") as f:
                _rules_cache = json.load(f)
            _rules_mtime = current_mtime
            print(f"🔄 [CASB] Reloaded {len(_rules_cache)} DLP rules from {RULES_FILE}")
    except Exception as e:
        print(f"❌ [CASB] Failed to load rules: {e}")
    return _rules_cache


class SecOpsGateway(CustomLogger):

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        prompt_str = str(data.get("messages", []))

        # Hard cap on prompt size to prevent prompt-stuffing
        if len(prompt_str) > 32000:
            print("\n🚨 [CASB ALERT] BLOCKED: Prompt exceeds maximum allowed size.")
            raise HTTPException(status_code=413, detail="CASB Policy Violation: Prompt too large.")

        # Run all DLP rules (hot-reloaded from JSON)
        rules = load_dlp_rules()
        for rule in rules:
            # Skip disabled rules
            if not rule.get("enabled", True):
                continue
            if re.search(rule["pattern"], prompt_str):
                print(f"\n🚨 [CASB ALERT] BLOCKED: {rule['name']} detected!")
                await self._log_to_splunk({
                    "action": "dlp_block",
                    "rule": rule["name"],
                    "severity": rule.get("severity", "high"),
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
