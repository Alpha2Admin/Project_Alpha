import re
import os
import json
import math
import time
import aiohttp
import asyncio
import urllib3
from collections import defaultdict
from litellm.integrations.custom_logger import CustomLogger
from fastapi import HTTPException
from prompt_classifier import classify_prompt, warmup as warmup_classifier

# ── v5.0 Modules ─────────────────────────────────────────────────────────────
from prompt_normalizer import normalize_prompt
from risk_scoring import record_event, get_user_score, is_quarantined, get_top_users
from conversation_tracker import tracker as conv_tracker
from quarantine_manager import quarantine

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── Splunk HEC Configuration ─────────────────────────────────────────────────
SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL", "https://localhost:8088/services/collector/event")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")
if not SPLUNK_HEC_TOKEN:
    print("⚠️ [CASB] WARNING: SPLUNK_HEC_TOKEN not set. Telemetry will fail silently.")

# ── Monitor-Only Mode ─────────────────────────────────────────────────────────
# When True: only CRITICAL threats are hard-blocked. All others are logged and allowed.
# When False: all threat levels block the request (original strict mode).
MONITOR_ONLY = os.getenv("CASB_MONITOR_ONLY", "true").lower() == "true"

# ── Canary Token Honeypot ─────────────────────────────────────────────────────
CANARY_TOKEN = os.getenv("CASB_CANARY_TOKEN", "sk-casb-fallback-secret-uuid")

# ── Risk-Based Detection Engine ───────────────────────────────────────────────
# Tracks per-user violation counts within a 2-minute sliding window.
# Thresholds (hits within 2 minutes) before Wazuh alert fires:
#   critical → 1   (ALWAYS hard-blocked + immediate alert)
#   high     → 3   (allowed, alert after 3 hits in 2 min)
#   medium   → 5   (allowed, alert after 5 hits in 2 min)
#   low      → 7   (allowed, alert after 7 hits in 2 min)
RISK_WINDOW_SECS = 120   # 2-minute sliding window
RISK_THRESHOLDS = {
    "critical": 1,
    "high":     3,
    "medium":   5,
    "low":      7,
}

# In-memory per-user event store: { user: { severity: [timestamp, ...] } }
_risk_counters: dict = defaultdict(lambda: defaultdict(list))
_risk_lock = asyncio.Lock()

# ── PII Redaction Patterns (for egress response filtering) ───────────────────
PII_REDACTION_PATTERNS = [
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), '[SSN-REDACTED]'),                # SSN
    (re.compile(r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b'),
     '[CC-REDACTED]'),                                                        # Credit Card
    (re.compile(r'(?i)(AKIA|ASIA|AROA)[A-Z0-9]{16}'), '[AWS-KEY-REDACTED]'), # AWS Key
    (re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END \1?PRIVATE KEY-----'),
     '[PRIVATE-KEY-REDACTED]'),                                               # Private Key
]

from inspection_engine import InspectionEngine
casb_engine = InspectionEngine(CANARY_TOKEN)

# ── LDAP Role-Based Access Control (RBAC) ────────────────────────────────────
def get_user_role_from_ldap(username: str) -> str:
    """
    Connects to the local OpenLDAP container to securely verify the user's role.
    Role Tiering:
    - 5001 = 'developer' (Allowed to use autonomous tools for git, npm, docker, etc.)
    - 5000 = 'standard'  (Prohibited from all autonomous system commands)
    """
    try:
        from ldap3 import Server, Connection, ALL
        # We use a 1-second timeout to prevent LDAP latency from blocking the AI response
        server = Server('ldap://127.0.0.1:389', get_info=ALL, connect_timeout=1)
        conn = Connection(server, 'cn=admin,dc=casb,dc=local', 'REDACTED_LDAP_PASS', auto_bind=True)
        conn.search('ou=People,dc=casb,dc=local', f'(uid={username})', attributes=['gidNumber'])
        if conn.entries:
            gid = str(conn.entries[0].gidNumber)
            if gid == '5001':
                return 'developer'
        return 'standard'
    except Exception as e:
        # Fail-safe: Default to standard if LDAP is unreachable
        print(f"⚠️ [CASB LDAP ERR] Failed to query LDAP for user {username}: {e}. Defaulting to standard tier.")
        return 'standard'


class SecOpsGateway(CustomLogger):
    """
    AI-CASB v5.0 — Full-Spectrum Behavioral Detection Gateway

    LAYER 0   (Pre-Processing):    Prompt normalizer (anti-evasion)
    LAYER 1   (Ingress - Entropy): Detects obfuscated/encoded payloads.
    LAYER 1.5 (Ingress - Semantic): DeBERTa classifier catches novel injections.
    LAYER 2   (Ingress - DLP):     Regex policy engine (AWS keys, PII, secrets).
    LAYER 3   (Egress  - Output):  Scans AI responses for leaks & canary exfil.
                                   Redacts PII inline before delivery.

    RISK ENGINE:   Persistent SQLite per-user scoring with time decay.
    CONV TRACKER:  Multi-turn attack detection (escalation, pivot, persistence).
    SOAR:          Auto-quarantine, rate limiting, model downgrade.
    """

    # ──────────────────────────────────────────────────────────────────────────
    # LAYER 0 + 1 + 1.5 + 2: INGRESS INSPECTION (Pre-Call Hook)
    # ──────────────────────────────────────────────────────────────────────────
    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        prompt_str = str(data.get("messages", []))
        user = self._extract_user(user_api_key_dict, data)

        # ── SOAR: Check if user is quarantined ────────────────────────────────
        risk_score, risk_level = get_user_score(user)
        soar_action, soar_detail = quarantine.check_and_enforce(
            user, risk_score, risk_level, data
        )
        if soar_action == "quarantined":
            print(f"\n🔒 [SOAR] QUARANTINED: '{user}' (score={risk_score})")
            await self._log_to_splunk({
                "action": "user_quarantined",
                "user": user,
                "risk_score": risk_score,
                "risk_level": risk_level,
            })
            raise HTTPException(status_code=403, detail=soar_detail)

        # ── LAYER 0.5: RBAC Tool Authorization (Ingress Check) ────────────────
        # If a standard user is even ASKING for tool use, we block it here to save tokens and ensure enforcement.
        role = get_user_role_from_ldap(user)
        if role == "standard":
            if "<execute_command>" in prompt_str or "execute_command" in prompt_str.lower():
                print(f"\n🚨 [CASB L0.5 RBAC BLOCK] Standard user '{user}' attempted to request tool use.")
                await self._handle_violation(
                    user=user,
                    severity="critical",
                    action="dlp_block",
                    layer="L0.5_RBAC_Tool_Control",
                    rule="Standard User - Unauthorized Tool Request",
                    extra={"alert": "A standard user attempted to invoke an autonomous tool. Access denied at ingress."},
                    prompt_preview=prompt_str[:500]
                )
                raise HTTPException(
                    status_code=403,
                    detail="CASB RBAC: Your profile (Standard) is not authorized to use autonomous AI tools. Please use the chat for text-based assistance only."
                )
        elif soar_action == "rate_limited":
            print(f"\n⏱️ [SOAR] RATE LIMITED: '{user}' (score={risk_score})")
            await self._log_to_splunk({
                "action": "user_rate_limited",
                "user": user,
                "risk_score": risk_score,
            })
            raise HTTPException(status_code=429, detail=soar_detail)

        if soar_action == "downgraded":
            print(f"⬇️ [SOAR] Model downgraded for '{user}' (score={risk_score})")

        # ── Extract clean user message for logging ────────────────────────────
        import re as _re
        user_messages = data.get("messages", [])
        last_user_msg = "(no user message found)"

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

        if last_user_msg == "(no user message found)":
            for msg in reversed(user_messages):
                if isinstance(msg, dict) and msg.get("role") == "user":
                    content = msg.get("content", "")
                    if isinstance(content, list):
                        content = " ".join(p.get("text", "") for p in content if isinstance(p, dict))
                    content = str(content)
                    cleaned = _re.sub(r'<[^>]+>.*?</[^>]+>', '', content, flags=_re.DOTALL).strip()
                    paragraphs = [p.strip() for p in cleaned.split('\n\n') if p.strip()]
                    if paragraphs:
                        last_user_msg = paragraphs[-1][:800]
                    elif cleaned:
                        last_user_msg = cleaned[-800:]
                    break

        # ── LAYER 0: Prompt Normalization (Anti-Evasion) ─────────────────────
        normalized_msg, norm_meta = normalize_prompt(last_user_msg)
        if norm_meta["evasion_detected"]:
            techniques = ", ".join(norm_meta["evasion_techniques"])
            print(f"\n🛡️ [CASB L0] Evasion attempt detected: [{techniques}] (edit_ratio={norm_meta['edit_distance_ratio']})")
            await self._log_to_splunk({
                "action": "evasion_attempt",
                "user": user,
                "evasion_techniques": techniques,
                "language": norm_meta["language"],
                "edit_distance_ratio": norm_meta["edit_distance_ratio"],
                "original_preview": last_user_msg[:200],
                "normalized_preview": normalized_msg[:200],
                "severity": "high",
            })
            # Record evasion in risk scoring
            record_event(user, "evasion_attempt", "high",
                         rule=f"Evasion: {techniques}", layer="L0_Normalizer")

        # Use normalized version for all inspection from here on
        inspection_input = normalized_msg

        # ── Hard size cap (always enforced, not severity-gated) ───────────────
        if len(prompt_str) > 1_000_000:
            print("\n🚨 [CASB L1] BLOCKED: Prompt exceeds 1M char size limit.")
            raise HTTPException(status_code=413, detail="CASB Policy Violation: Prompt too large.")

        # ── LAYER 1: Shannon Entropy Analysis ────────────────────────────────
        is_suspicious, entropy_score, snippet = casb_engine.check_entropy_violations(inspection_input)
        if is_suspicious:
            severity = "critical"
            print(f"\n🚨 [CASB L1] Entropy violation ({entropy_score}) — obfuscated payload detected.")
            await self._handle_violation(
                user=user,
                severity=severity,
                action="dlp_block" if not MONITOR_ONLY else "dlp_monitor",
                layer="L1_Entropy_Analysis",
                rule="Obfuscated Payload Detected",
                extra={"entropy_score": entropy_score, "snippet": snippet},
                prompt_preview=last_user_msg
            )
            # Critical is ALWAYS hard-blocked
            raise HTTPException(
                status_code=403,
                detail="CASB Policy Violation: Obfuscated or Base64-encoded payload detected."
            )

        # ── LAYER 1.5: Semantic Prompt Injection Classifier ───────────────────
        classifier_input = inspection_input[:512]
        if classifier_input and len(classifier_input) > 10:
            try:
                result = casb_engine.check_semantic_injection(classifier_input)
                print(f"🧠 [CASB L1.5] Semantic: {result['label']} (injection={result['injection_score']}, {result['latency_ms']}ms)")
                if result["blocked"]:
                    severity = "critical"
                    print(f"\n🚨 [CASB L1.5] Injection detected (confidence={result['injection_score']}).")
                    await self._handle_violation(
                        user=user,
                        severity=severity,
                        action="dlp_block",
                        layer="L1.5_Semantic_Classifier",
                        rule="Prompt Injection (Semantic/DeBERTa)",
                        extra={"injection_score": result["injection_score"], "safe_score": result["safe_score"]},
                        prompt_preview=last_user_msg
                    )
                    # Critical = ALWAYS blocked
                    raise HTTPException(
                        status_code=403,
                        detail=f"CASB Policy Violation: Prompt injection detected (confidence: {result['injection_score']:.0%})."
                    )
            except HTTPException:
                raise
            except Exception as e:
                print(f"⚠️ [CASB L1.5] Classifier error (falling through): {e}")

        # ── LAYER 2: DLP Regex Scan ───────────────────────────────────────────
        rule_violation = casb_engine.check_dlp_ingress(inspection_input)
        if rule_violation:
            rule = rule_violation
            severity = rule.get("severity", "high")
            print(f"\n{'🚨' if severity == 'critical' else '⚠️'} [CASB L2] DLP match: {rule['name']} (severity={severity})")

            # Determine action: critical = block, everything else = flag and allow
            action = "dlp_block" if severity == "critical" else "dlp_flagged"

            await self._handle_violation(
                user=user,
                severity=severity,
                action=action,
                layer="L2_DLP_Regex",
                rule=rule["name"],
                extra={},
                prompt_preview=last_user_msg
            )

            # ONLY critical gets blocked — high/medium/low are allowed through
            if severity == "critical":
                raise HTTPException(status_code=403, detail=rule["detail"])
            else:
                print(f"👁️ [CASB] {severity.upper()} threat flagged and allowed through.")

        # ── Record benign event in conversation tracker ───────────────────────
        conv_tracker.record(user, last_user_msg, "ai_inference", "none", "", "")

        # ── Multi-Turn Pattern Detection ─────────────────────────────────────
        pattern = conv_tracker.detect_patterns(user)
        if pattern:
            print(f"\n🔍 [CASB MULTI-TURN] Pattern detected: {pattern['pattern']} for '{user}'")
            await self._log_to_splunk({
                "action": "multi_turn_pattern",
                "user": user,
                "pattern_type": pattern["pattern"],
                "pattern_description": pattern["description"],
                "mitre_attack": ", ".join(pattern.get("mitre_attack", [])),
                "mitre_atlas": ", ".join(pattern.get("mitre_atlas", [])),
                "severity": "high",
            })
            # Boost risk score for multi-turn patterns
            record_event(user, "dlp_flagged", "high",
                         rule=f"Multi-Turn: {pattern['pattern']}", layer="Conv_Tracker")

        return data

    # ──────────────────────────────────────────────────────────────────────────
    # LAYER 3: EGRESS INSPECTION (Post-Call Success Hook)
    # ──────────────────────────────────────────────────────────────────────────
    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        try:
            response_text = response_obj.choices[0].message.content if response_obj else ""
            total_tokens = response_obj.usage.total_tokens if response_obj else 0
            user = self._extract_user_from_kwargs(kwargs)

            # ── Canary Token Detection (always critical, always blocked) ──────
            if CANARY_TOKEN in response_text:
                print("\n🚨🚨 [CASB L3 CRITICAL] CANARY TOKEN IN RESPONSE! System prompt exfiltrated!")
                await self._handle_violation(
                    user=user,
                    severity="critical",
                    action="intrusion_detected",
                    layer="L3_Canary_Honeypot",
                    rule="Canary Token Exfiltration",
                    extra={"alert": "Attacker successfully extracted system prompt. IMMEDIATE LOCKDOWN REQUIRED."},
                    prompt_preview=response_text[:500]
                )
                raise HTTPException(
                    status_code=403,
                    detail="CASB Critical: System prompt exfiltration blocked. Incident logged."
                )

            # ── Egress DLP Scan ───────────────────────────────────────────────
            rule_violation, matched_snippet = casb_engine.check_dlp_egress(response_text)
            if rule_violation:
                rule = rule_violation
                severity = rule.get("severity", "high")
                print(f"\n🚨 [CASB L3 EGRESS] AI response violation: {rule['name']} (severity={severity})")
                await self._handle_violation(
                    user=user,
                    severity=severity,
                    action="egress_block" if (severity == "critical" or not MONITOR_ONLY) else "egress_flagged",
                    layer="L3_Egress_Filter",
                    rule=rule["name"],
                    extra={"alert": "AI response contained sensitive data."},
                    prompt_preview=response_text[:500]
                )
                if severity == "critical" or not MONITOR_ONLY:
                    raise HTTPException(
                        status_code=403,
                        detail=f"CASB Egress Violation: AI response contained {rule['name']}. Response suppressed."
                    )
                print(f"👁️ [CASB MONITOR] Egress {severity.upper()} logged and allowed.")

            # ── LAYER 4: Agent Action Governance (Pre-Execution RBAC & DLP) ───────────
            import re
            action_match = re.search(r'<execute_command>(.*?)</execute_command>', response_text, re.DOTALL)
            if action_match:
                cmd = action_match.group(1).strip()
                
                # Fetch identity-aware role from LDAP
                role = get_user_role_from_ldap(user)
                
                if role == "standard":
                    # This is a fail-safe in case it bypassed the ingress check
                    print(f"\n🚨 [CASB L4 RBAC BLOCK] Unauthorized tool output detected for '{user}'")
                    # Note: Raising here is non-blocking in some LiteLLM versions, 
                    # so we rely primarily on the Ingress check (Layer 0.5).
                    await self._handle_violation(
                        user=user,
                        severity="critical",
                        action="egress_block",
                        layer="L4_Action_Governance_RBAC",
                        rule="Standard User - Prohibited Tool Use (Egress Catch)",
                        extra={
                            "alert": "Tool execution tag detected in response for unauthorized user. Response should be discarded.",
                            "unauthorized_command": cmd[:200]
                        },
                        prompt_preview=response_text[:500]
                    )
                else:
                    # ── Developer Role: Context-Aware Filtering ──────────────────────
                    # Developers are ALLOWED to use: git, npm, pip, docker, kubectl, terraform, aws, gcloud, etc.
                    # Developers are BLOCKED from: network shells, registry modification, root filesystem deletion.
                    
                    # Prohibited commands are specific to "Attacker" patterns, not "Developer" patterns.
                    prohibited_dev_cmds = [
                        "nc ", "bash -i", "sh -i", "/dev/tcp", 
                        "powershell -enc", "powershell.exe -enc", 
                        "reg add", "rm -rf /", "chmod 777",
                        "reverse_shell", "bind_shell"
                    ]
                    
                    cmd_lower = cmd.lower()
                    for bad in prohibited_dev_cmds:
                        if bad in cmd_lower:
                            print(f"\n🚨 [CASB L4 ACTION BLOCK] Developer '{user}' attempted restricted command: {bad}")
                            await self._handle_violation(
                                user=user,
                                severity="critical",
                                action="egress_block",
                                layer="L4_Action_Governance",
                                rule=f"Developer Restricted Command Usage ({bad})",
                                extra={
                                    "alert": "Elevated user attempted to execute a restricted/dangerous system command.",
                                    "command": cmd[:200]
                                },
                                prompt_preview=response_text[:500]
                            )
                            raise HTTPException(
                                status_code=403,
                                detail=f"CASB Action Governance: Command '{bad}' is restricted even for developers due to high risk of reverse-shell or system damage."
                            )
                    
                    # Log successful authorized tool usage for developers (monitoring for audit)
                    # Allowed tools include: git, npm, pip, docker, kubectl, terraform, ls, cat, etc.
                    print(f"✅ [CASB L4 RBAC ALLOW] Developer '{user}' authorized to execute: {cmd[:50]}...")
                    await self._log_to_splunk({
                        "action": "tool_execution_authorized",
                        "user": user,
                        "role": "developer",
                        "command": cmd[:200],
                        "status": "allowed"
                    })

            # ── PII Redaction on Response (Option B: Redact inline) ───────────
            redacted_text, redaction_count = self._redact_pii(response_text)
            if redaction_count > 0:
                print(f"🔏 [CASB L3] Redacted {redaction_count} PII instance(s) from response.")
                # Mutate the response object to return redacted text
                response_obj.choices[0].message.content = redacted_text
                await self._log_to_splunk({
                    "action": "egress_redacted",
                    "user": user,
                    "redaction_count": redaction_count,
                    "severity": "medium",
                    "layer": "L3_PII_Redaction",
                })
                record_event(user, "egress_flagged", "medium",
                             rule="PII Redaction Applied", layer="L3_PII_Redaction")

            # ── Normal Success Log ────────────────────────────────────────────
            risk_score, risk_level = get_user_score(user)
            await self._log_to_splunk({
                "action": "ai_inference",
                "layer": "Allowed",
                "model": kwargs.get("model", "unknown"),
                "user": user,
                "prompt_preview": str(kwargs.get("messages", []))[:500],
                "response_preview": redacted_text[:500] if redaction_count > 0 else response_text[:500],
                "total_tokens": total_tokens,
                "duration_ms": (end_time - start_time).total_seconds() * 1000,
                "status": "success",
                "risk_score": risk_score,
                "risk_level": risk_level,
            })

        except HTTPException:
            raise
        except Exception as e:
            print(f"❌ [CASB EGRESS ERROR]: {e}")

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        try:
            user = self._extract_user_from_kwargs(kwargs)
            await self._log_to_splunk({
                "action": "ai_inference_failure",
                "model": kwargs.get("model", "unknown"),
                "user": user,
                "error": str(kwargs.get("exception", "Unknown error")),
                "duration_ms": (end_time - start_time).total_seconds() * 1000,
                "status": "failure"
            })
        except Exception as e:
            print(f"❌ [SPLUNK FAILURE LOG ERROR]: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # RISK ENGINE
    # ──────────────────────────────────────────────────────────────────────────
    async def _handle_violation(
        self,
        user: str,
        severity: str,
        action: str,
        layer: str,
        rule: str,
        extra: dict,
        prompt_preview: str
    ):
        """
        Central violation handler:
        1. Logs event to Splunk.
        2. Records in persistent risk scoring DB.
        3. Records in conversation tracker.
        4. Sends to Wazuh for forensic investigation.
        5. Updates sliding-window counter.
        """
        now = time.time()

        # ── 1. Record in risk scoring DB ─────────────────────────────────────
        risk_score, risk_level = record_event(user, action, severity, rule=rule, layer=layer)

        # ── 2. Record in conversation tracker ────────────────────────────────
        conv_tracker.record(user, prompt_preview, action, severity, rule, layer)

        # ── 3. Log to Splunk (enriched with risk data) ───────────────────────
        event = {
            "action": action,
            "layer": layer,
            "rule": rule,
            "severity": severity,
            "user": user,
            "prompt_preview": prompt_preview,
            "monitor_only": MONITOR_ONLY,
            "risk_score": risk_score,
            "risk_level": risk_level,
            **extra
        }
        await self._log_to_splunk(event)

        # ── 4. Send to Wazuh (for forensic investigation + MITRE heatmap) ────
        await self._send_to_wazuh({
            "source": "ai-casb",
            "action": action,
            "layer": layer,
            "rule": rule,
            "severity": severity,
            "user": user,
            "prompt_preview": prompt_preview[:300],
            "risk_score": str(risk_score),
            "risk_level": risk_level,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            **{k: str(v) for k, v in extra.items()}
        })

        # ── 5. Update sliding-window counter (for Splunk dashboard) ──────────
        async with _risk_lock:
            _risk_counters[user][severity] = [
                ts for ts in _risk_counters[user][severity]
                if now - ts < RISK_WINDOW_SECS
            ]
            _risk_counters[user][severity].append(now)
            count = len(_risk_counters[user][severity])

        threshold = RISK_THRESHOLDS.get(severity, 99)
        print(f"📊 [RISK] {user} | {severity.upper()} | count={count}/{threshold} | score={risk_score} | level={risk_level}")

        # ── 6. Threshold breach → log to Splunk ─────────────────────────────
        if count >= threshold:
            await self._fire_wazuh_alert(user=user, severity=severity, rule=rule, count=count)
            async with _risk_lock:
                _risk_counters[user][severity] = []

        # ── 7. Check multi-turn patterns after each violation ────────────────
        pattern = conv_tracker.detect_patterns(user)
        if pattern:
            print(f"\n🔍 [MULTI-TURN] {pattern['pattern']}: {pattern['description']}")
            await self._log_to_splunk({
                "action": "multi_turn_pattern",
                "user": user,
                "pattern_type": pattern["pattern"],
                "pattern_description": pattern["description"],
                "mitre_attack": ", ".join(pattern.get("mitre_attack", [])),
                "mitre_atlas": ", ".join(pattern.get("mitre_atlas", [])),
                "severity": "high",
                "risk_score": risk_score,
            })

    async def _fire_wazuh_alert(self, user: str, severity: str, rule: str, count: int):
        """
        Logs a threshold breach to Splunk so the dashboard shows it.
        The actual Wazuh alert is handled by Wazuh's own frequency rules.
        """
        print(f"\n🚨🔔 [WAZUH ALERT] {severity.upper()} threshold breached for '{user}' | {count} hits in {RISK_WINDOW_SECS}s!")
        await self._log_to_splunk({
            "action": "wazuh_alert_fired",
            "severity": severity,
            "user": user,
            "rule": rule,
            "violation_count": count,
            "status": f"{severity.upper()}_BEHAVIORAL_RISK"
        })

    async def _send_to_wazuh(self, event: dict):
        """
        Writes a JSON event into the Wazuh Manager container's monitored log.
        Multi-VM: SSH into the Wazuh VM → docker exec into the container.
        Single-machine: docker exec directly (fallback).
        """
        WAZUH_MANAGER_IP = os.getenv("WAZUH_MANAGER_IP", "")
        WAZUH_CONTAINER = os.getenv("WAZUH_CONTAINER", "single-node-wazuh.manager-1")
        WAZUH_LOG_PATH = "/var/ossec/logs/casb_risk_alerts.json"
        json_line = json.dumps(event) + "\n"
        
        try:
            if WAZUH_MANAGER_IP:
                # Multi-VM: SSH → docker exec via stdin
                cmd = (
                    f"ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 "
                    f"usr@{WAZUH_MANAGER_IP} "
                    f"'sudo docker exec -i {WAZUH_CONTAINER} "
                    f"bash -c \"cat >> {WAZUH_LOG_PATH}\"'"
                )
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
            else:
                # Single-machine fallback: direct docker exec via stdin
                cmd = f"docker exec -i {WAZUH_CONTAINER} bash -c 'cat >> {WAZUH_LOG_PATH}'"
                proc = await asyncio.create_subprocess_shell(
                    cmd,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
            _, stderr = await asyncio.wait_for(proc.communicate(input=json_line.encode()), timeout=5)
            if proc.returncode == 0:
                print(f"🛡️ [WAZUH] Event sent | severity={event.get('severity')} | rule={event.get('rule')}")
            else:
                print(f"⚠️ [WAZUH] Failed: {stderr.decode().strip()[:100]}")
        except Exception as e:
            print(f"⚠️ [WAZUH] Could not send event: {e}")

    # ──────────────────────────────────────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────────────────────────────────────
    def _extract_user(self, user_api_key_dict, data=None) -> str:
        """
        Extract user identity from multiple sources (priority order):
        1. x-user-id header (via LiteLLM metadata)
        2. 'user' field in request body
        3. LiteLLM API key user_id
        4. Fallback: 'anonymous'
        """
        # Source 1: Check metadata for x-user-id header
        if data:
            metadata = data.get("metadata", {}) or {}
            headers = metadata.get("headers", {}) or {}
            x_user = headers.get("x-user-id") or headers.get("X-User-Id")
            if x_user:
                return str(x_user)

            # Source 2: 'user' field in request body
            body_user = data.get("user")
            if body_user:
                return str(body_user)

        # Source 3: LiteLLM API key mapping
        try:
            if hasattr(user_api_key_dict, 'user_id') and getattr(user_api_key_dict, 'user_id'):
                return str(getattr(user_api_key_dict, 'user_id'))
            if isinstance(user_api_key_dict, dict) and user_api_key_dict.get('user_id'):
                return str(user_api_key_dict.get('user_id'))
        except Exception:
            pass

        return "anonymous"

    def _extract_user_from_kwargs(self, kwargs) -> str:
        """Extract user from kwargs (used in post-call hooks)."""
        metadata = kwargs.get("litellm_params", {}).get("metadata", {}) or {}
        headers = metadata.get("headers", {}) or {}
        x_user = headers.get("x-user-id") or headers.get("X-User-Id")
        if x_user:
            return str(x_user)
        body_user = kwargs.get("user")
        if body_user:
            return str(body_user)
        return "anonymous"

    def _redact_pii(self, text: str) -> tuple:
        """
        Redact PII patterns from response text (Option B: inline redaction).
        Returns (redacted_text, redaction_count).
        """
        if not text:
            return text, 0
        count = 0
        for pattern, replacement in PII_REDACTION_PATTERNS:
            matches = pattern.findall(text)
            if matches:
                count += len(matches) if isinstance(matches[0], str) else len(matches)
                text = pattern.sub(replacement, text)
        return text, count

    async def _log_to_splunk(self, event_data: dict):
        """Fire telemetry to Splunk HEC asynchronously. Non-blocking — failures are silently ignored."""
        if not SPLUNK_HEC_TOKEN:
            return
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
                    print(f"📡 [SPLUNK] Event logged | HTTP {resp.status} | action={event_data.get('action')}")
        except Exception as e:
            print(f"❌ [SPLUNK SEND ERROR]: {e}")


proxy_handler_instance = SecOpsGateway()
