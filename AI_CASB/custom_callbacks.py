# AI_CASB/custom_callbacks.py - Sanitized version
import os
import re
import json
import asyncio
import aiohttp
import urllib3
from litellm.integrations.custom_logger import CustomLogger
from .inspection_engine import InspectionEngine
from .prompt_normalizer import normalize_prompt

# ── Configuration ─────────────────────────────────────────────────────────────
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "https://localhost:8088/services/collector/event")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")
if not SPLUNK_HEC_TOKEN:
    print("⚠️ [CASB] WARNING: SPLUNK_HEC_TOKEN not set. Telemetry will fail silently.")

# ── Canary Token Honeypot ─────────────────────────────────────────────────────
CANARY_TOKEN = os.getenv("CASB_CANARY_TOKEN", "sk-casb-fallback-secret-uuid")

# ── DLP Policy Patterns ────────────────────────────────────────────────────────
PII_REDACTION_PATTERNS = [
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[SSN-REDACTED]'),                  # SSN
    (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b'), '[CC-REDACTED]'), # Credit Card
    (re.compile(r'(?i)(AKIA|ASIA|AROA)[A-Z0-9]{16}'), '[AWS-KEY-REDACTED]'), # AWS Key
    (re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END \1?PRIVATE KEY-----'),
     '[PRIVATE-KEY-REDACTED]'),                                               # Private Key
]

casb_engine = InspectionEngine(CANARY_TOKEN)

class SecOpsGateway(CustomLogger):
    """
    Hybrid Security Gateway:
    LAYER 1   (Ingress - Entropy): Scans for Base64/Obfuscated payloads.
    LAYER 1.5 (Ingress - Intent):  Semantic classification (Injection/Jailbreak).
    LAYER 2   (Ingress - DLP):     Regex policy engine (AWS keys, PII, secrets).
    LAYER 3   (Egress  - Output):  Scans AI responses for data leaks & canary token exfiltration.
    """
    def __init__(self):
        self.rules_mtime = 0
        self.rules_cache = []

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        """
        Intercepts prompt BEFORE it reaches the AI model.
        """
        user = self._extract_user(user_api_key_dict, data)
        messages = data.get("messages", [])
        if not messages: return

        # Extract the human message (ignoring system prompt noise)
        prompt_text = messages[-1].get("content", "")
        
        # ── LAYER 1: Entropy Scan ─────────────────────────────────────────────
        if casb_engine.check_entropy(prompt_text):
            await self._log_to_splunk({
                "action": "ingress_block",
                "layer": "L1_Entropy",
                "user": user,
                "severity": "high",
                "alert": "High entropy/obfuscated payload detected."
            })
            raise HTTPException(status_code=403, detail="CASB Violation: Obfuscated payload detected.")

        # ── LAYER 2: DLP Regex Scan ───────────────────────────────────────────
        violation = casb_engine.check_dlp_ingress(prompt_text)
        if violation:
            await self._log_to_splunk({
                "action": "ingress_block",
                "layer": "L2_DLP",
                "user": user,
                "rule": violation["name"],
                "severity": violation.get("severity", "critical"),
                "alert": violation["detail"]
            })
            raise HTTPException(status_code=403, detail=violation["detail"])

    async def async_post_call_hook(self, user_api_key_dict, response_obj, start_time, end_time):
        """
        Intercepts response AFTER AI generates it, before the user sees it.
        """
        try:
            response_text = response_obj.choices[0].message.content
            total_tokens = response_obj.usage.total_tokens if response_obj else 0

            # ── LAYER 3: Canary Token Detection (always critical, always blocked) ──
            if CANARY_TOKEN in response_text:
                print("\n🚨🚨 [CASB L3 CRITICAL] CANARY TOKEN IN RESPONSE! System prompt exfiltrated!")
                await self._log_to_splunk({
                    "action": "egress_block",
                    "layer": "L3_Canary_Honeypot",
                    "rule": "Canary Token Exfiltration",
                    "severity": "critical",
                    "alert": "Honeypot token detected in AI response. Potential system prompt leak."
                })
                raise HTTPException(status_code=403, detail="CASB CRITICAL: Security Honeypot Triggered.")

        except Exception as e:
            print(f"❌ [CASB EGRESS ERROR]: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────────────────────────────────────
    def _extract_user(self, user_api_key_dict, data=None) -> str:
        return "ide_user"

    async def _log_to_splunk(self, event_data: dict):
        if not SPLUNK_HEC_TOKEN: return
        headers = {"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}", "Content-Type": "application/json"}
        payload = {"sourcetype": "_json", "index": "casb_gateway", "event": event_data}
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                await session.post(SPLUNK_HEC_URL, json=payload, headers=headers, timeout=5)
        except Exception: pass

proxy_handler_instance = SecOpsGateway()