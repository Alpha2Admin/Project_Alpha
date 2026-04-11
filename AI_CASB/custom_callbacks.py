import re
import os
import json
import math
import aiohttp
import asyncio
import urllib3
from litellm.integrations.custom_logger import CustomLogger
from fastapi import HTTPException
from prompt_classifier import classify_prompt, warmup as warmup_classifier

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_HEC_URL = "https://localhost:8088/services/collector/event"
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")
if not SPLUNK_HEC_TOKEN:
    print("⚠️ [CASB] WARNING: SPLUNK_HEC_TOKEN not set. Telemetry will fail.")

# ── Canary Token Honeypot ────────────────────────────────────────────────────
# This fake secret is injected into the LLM system prompt via config.yaml.
# If the model ever outputs this in a response, it means an attacker successfully
# extracted the hidden system prompt. The gateway will immediately fire a CRITICAL alert.
CANARY_TOKEN = os.getenv("CASB_CANARY_TOKEN", "sk-casb-fallback-canary-uuid-change-me")

# ── Entropy Thresholds (Anti-Obfuscation / Anti-Base64) ──────────────────────
# Natural English hovers around 3.5-4.2 entropy.
# Base64, hex, and dense leetspeak typically spike above 4.8.
ENTROPY_BLOCK_THRESHOLD = 4.8
ENTROPY_MIN_SCAN_LENGTH = 50  # Only compute entropy on tokens long enough to matter

# ── Dynamic DLP Rules (hot-reload from JSON) ─────────────────────────────────
RULES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dlp_rules.json")
_rules_cache = []
_rules_mtime = 0

def load_dlp_rules():
    """Load DLP rules from JSON file. Hot-reloads automatically when the file changes."""
    global _rules_cache, _rules_mtime
    try:
        current_mtime = os.path.getmtime(RULES_FILE)
        if current_mtime != _rules_mtime:
            with open(RULES_FILE, "r") as f:
                raw_rules = f.read()
                # Dynamically inject the canary token into the rules so it's not hardcoded in the JSON file
                raw_rules = raw_rules.replace("CASB_CANARY_TOKEN_PLACEHOLDER", CANARY_TOKEN)
                _rules_cache = json.loads(raw_rules)
            _rules_mtime = current_mtime
            print(f"🔄 [CASB] Reloaded {len(_rules_cache)} DLP rules from {RULES_FILE} (Canary Injection Active)")
    except Exception as e:
        print(f"❌ [CASB] Failed to load DLP rules: {e}")
    return _rules_cache


def compute_shannon_entropy(text: str) -> float:
    """
    Compute Shannon entropy of a string.
    High entropy (> 4.8) typically indicates base64, hex encoding, or dense obfuscation.
    """
    if not text:
        return 0.0
    frequency = {}
    for char in text:
        frequency[char] = frequency.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in frequency.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def check_entropy_violations(text: str) -> tuple:
    """
    Scan prompt tokens and sliding windows for high-entropy obfuscated payloads.
    Returns (is_suspicious: bool, max_entropy_score: float, offending_snippet: str)
    """
    words = text.split()

    # Check individual long tokens (Base64 blobs are typically single dense words)
    for word in words:
        if len(word) >= ENTROPY_MIN_SCAN_LENGTH:
            score = compute_shannon_entropy(word)
            if score >= ENTROPY_BLOCK_THRESHOLD:
                return True, round(score, 2), word[:80]

    # Sliding window check across the full text (catches distributed leetspeak)
    if len(text) >= ENTROPY_MIN_SCAN_LENGTH:
        for i in range(0, len(text) - 60, 40):
            chunk = text[i:i + 80]
            if len(chunk) >= ENTROPY_MIN_SCAN_LENGTH:
                score = compute_shannon_entropy(chunk)
                if score >= ENTROPY_BLOCK_THRESHOLD:
                    return True, round(score, 2), chunk[:80]

    return False, 0.0, ""


class SecOpsGateway(CustomLogger):
    """
    AI-CASB v3.0 — Four-Layer Hybrid Security Gateway

    LAYER 1   (Ingress - Entropy):   Blocks obfuscated/encoded payloads (Base64, Leetspeak)
    LAYER 1.5 (Ingress - Semantic):  DeBERTa classifier detects novel prompt injections by intent
    LAYER 2   (Ingress - DLP):       Blocks prompts matching regex policy rules (AWS keys, PII)
    LAYER 3   (Egress  - Output):    Scans AI responses for data leaks & canary token exfiltration
    """

    # ──────────────────────────────────────────────────────────────────────────
    # LAYER 1 + 2: INGRESS INSPECTION (Pre-Call Hook)
    # ──────────────────────────────────────────────────────────────────────────
    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        prompt_str = str(data.get("messages", []))

        # ── Extract the user's actual message early (used for logging across all layers) ──
        # We scan prompt_str (the full array) for security, but log only last_user_msg
        # so Splunk shows the developer's input — not Cline's XML wrapper or directory listing.
        import re as _re
        user_messages = data.get("messages", [])
        last_user_msg = "(no user message found)"

        # First pass: search ALL user messages for the last <task> tag (most reliable)
        for msg in reversed(user_messages):
            if isinstance(msg, dict) and msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, list):
                    content = " ".join(p.get("text", "") for p in content if isinstance(p, dict))
                content = str(content)

                task_match = _re.search(r'<task>(.*?)</task>', content, _re.DOTALL)
                if task_match:
                    last_user_msg = task_match.group(1).strip()[:800]
                    break

        # Fallback: if no <task> tag found, take the last paragraph of the last user message.
        # In Cline multi-turn, the human's actual input is always the last paragraph,
        # above it is tool-use error text and retry instructions that confuse the classifier.
        if last_user_msg == "(no user message found)":
            for msg in reversed(user_messages):
                if isinstance(msg, dict) and msg.get("role") == "user":
                    content = msg.get("content", "")
                    if isinstance(content, list):
                        content = " ".join(p.get("text", "") for p in content if isinstance(p, dict))
                    content = str(content)
                    # Strip all XML blocks
                    cleaned = _re.sub(r'<[^>]+>.*?</[^>]+>', '', content, flags=_re.DOTALL).strip()
                    # Take the last non-empty paragraph (the human's actual question)
                    paragraphs = [p.strip() for p in cleaned.split('\n\n') if p.strip()]
                    if paragraphs:
                        last_user_msg = paragraphs[-1][:800]
                    elif cleaned:
                        last_user_msg = cleaned[-800:]
                    break

        # Hard cap on prompt size to prevent prompt-stuffing (1M chars supports full agent contexts)
        if len(prompt_str) > 1_000_000:
            print("\n🚨 [CASB L1] BLOCKED: Prompt exceeds 1M char size limit.")
            raise HTTPException(status_code=413, detail="CASB Policy Violation: Prompt too large.")

        # ── LAYER 1: Shannon Entropy Analysis (Anti-Obfuscation) ────────────
        is_suspicious, entropy_score, snippet = check_entropy_violations(last_user_msg)
        if is_suspicious:
            print(f"\n🚨 [CASB L1] BLOCKED: High entropy payload ({entropy_score}) — possible Base64/obfuscation attack!")
            await self._log_to_splunk({
                "action": "dlp_block",
                "layer": "L1_Entropy_Analysis",
                "rule": "Obfuscated Payload Detected",
                "severity": "critical",
                "user": self._extract_user(user_api_key_dict),
                "entropy_score": entropy_score,
                "snippet": snippet,
                "prompt_preview": last_user_msg
            })
            raise HTTPException(
                status_code=403,
                detail="CASB Policy Violation: Obfuscated or Base64-encoded payload detected. Encoding injections are forbidden."
            )
        # ── LAYER 1.5: Semantic Prompt Injection Classifier (DeBERTa) ───────
        # Only classify the user's actual message (not the full Cline system prompt)
        classifier_input = last_user_msg[:512]

        if classifier_input and len(classifier_input) > 10:
            try:
                result = classify_prompt(classifier_input)
                print(f"🧠 [CASB L1.5] Semantic scan: {result['label']} (injection={result['injection_score']}, latency={result['latency_ms']}ms)")
                if result["blocked"]:
                    print(f"\n🚨 [CASB L1.5] BLOCKED: Semantic classifier detected prompt injection! (confidence={result['injection_score']})")
                    await self._log_to_splunk({
                        "action": "dlp_block",
                        "layer": "L1.5_Semantic_Classifier",
                        "rule": "Prompt Injection (Semantic/DeBERTa)",
                        "severity": "critical",
                        "user": self._extract_user(user_api_key_dict),
                        "injection_score": result["injection_score"],
                        "safe_score": result["safe_score"],
                        "classifier_latency_ms": result["latency_ms"],
                        "prompt_preview": last_user_msg
                    })
                    raise HTTPException(
                        status_code=403,
                        detail=f"CASB Policy Violation: Semantic analysis detected a prompt injection attempt (confidence: {result['injection_score']:.0%}). Request blocked."
                    )
            except HTTPException:
                raise
            except Exception as e:
                print(f"⚠️ [CASB L1.5] Classifier error (falling through to regex): {e}")

        # ── LAYER 2: DLP Regex Scan (Hot-reloaded from dlp_rules.json) ──────
        rules = load_dlp_rules()
        for rule in rules:
            if not rule.get("enabled", True):
                continue
            if re.search(rule["pattern"], last_user_msg):
                print(f"\n🚨 [CASB L2] BLOCKED: {rule['name']} detected!")
                await self._log_to_splunk({
                    "action": "dlp_block",
                    "layer": "L2_DLP_Regex",
                    "rule": rule["name"],
                    "severity": rule.get("severity", "high"),
                    "user": self._extract_user(user_api_key_dict),
                    "prompt_preview": last_user_msg
                })
                raise HTTPException(status_code=403, detail=rule["detail"])

        return data

    # ──────────────────────────────────────────────────────────────────────────
    # LAYER 3: EGRESS INSPECTION (Post-Call Success Hook)
    # ──────────────────────────────────────────────────────────────────────────
    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        try:
            response_text = response_obj.choices[0].message.content if response_obj else ""
            total_tokens = response_obj.usage.total_tokens if response_obj else 0

            # ── Canary Token Detection ────────────────────────────────────────
            if CANARY_TOKEN in response_text:
                print("\n🚨🚨 [CASB L3 CRITICAL] CANARY TOKEN IN RESPONSE! System prompt was exfiltrated!")
                await self._log_to_splunk({
                    "action": "intrusion_detected",
                    "layer": "L3_Canary_Honeypot",
                    "rule": "Canary Token Exfiltration",
                    "severity": "critical",
                    "user": "ide_user",
                    "alert": "Attacker successfully extracted system prompt. IMMEDIATE LOCKDOWN REQUIRED.",
                    "response_preview": response_text[:500]
                })
                raise HTTPException(
                    status_code=403,
                    detail="CASB Critical Security Alert: Hostile system extraction blocked. Incident logged."
                )

            # ── Egress DLP Scan (scan the AI's output before returning it) ──
            rules = load_dlp_rules()
            for rule in rules:
                if not rule.get("enabled", True):
                    continue
                # Skip jailbreak/injection rules for egress (they are ingress-only)
                if rule.get("scope", "both") == "ingress":
                    continue
                if re.search(rule["pattern"], response_text):
                    print(f"\n🚨 [CASB L3 EGRESS] AI response contains policy violation: {rule['name']} — SUPPRESSING!")
                    await self._log_to_splunk({
                        "action": "egress_block",
                        "layer": "L3_Egress_Filter",
                        "rule": rule["name"],
                        "severity": rule.get("severity", "high"),
                        "user": "ide_user",
                        "alert": "AI-generated response contained sensitive data. Response suppressed before delivery.",
                        "response_preview": response_text[:500]
                    })
                    raise HTTPException(
                        status_code=403,
                        detail=f"CASB Egress Violation: AI response contained sensitive data ({rule['name']}). Response suppressed."
                    )

            # ── Normal Success Log ────────────────────────────────────────────
            await self._log_to_splunk({
                "action": "ai_inference",
                "layer": "Allowed",
                "model": kwargs.get("model", "unknown"),
                "user": "ide_user",
                "prompt_preview": str(kwargs.get("messages", []))[:500],
                "response_preview": response_text[:500],
                "total_tokens": total_tokens,
                "duration_ms": (end_time - start_time).total_seconds() * 1000,
                "status": "success"
            })

        except HTTPException:
            raise
        except Exception as e:
            print(f"❌ [CASB EGRESS ERROR]: {e}")

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

    # ──────────────────────────────────────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────────────────────────────────────
    def _extract_user(self, user_api_key_dict) -> str:
        """Safely extract clean user identifier from LiteLLM key dict."""
        try:
            if hasattr(user_api_key_dict, 'user_id') and getattr(user_api_key_dict, 'user_id'):
                return str(getattr(user_api_key_dict, 'user_id'))
            if isinstance(user_api_key_dict, dict) and user_api_key_dict.get('user_id'):
                return str(user_api_key_dict.get('user_id'))
        except Exception:
            pass
        return "ide_user"

    async def _log_to_splunk(self, event_data: dict):
        """Fire telemetry to Splunk HEC asynchronously."""
        headers = {
            "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
            "Content-Type": "application/json"
        }
        payload = {"sourcetype": "_json", "index": "casb_gateway", "event": event_data}
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=False)) as session:
                async with session.post(
                    SPLUNK_HEC_URL, json=payload, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as resp:
                    print(f"📡 [SPLUNK] Event logged | HTTP {resp.status}")
        except Exception as e:
            print(f"❌ [SPLUNK SEND ERROR]: {e}")


proxy_handler_instance = SecOpsGateway()
