import os
import re
import json
import threading
import requests as http_requests
from mitmproxy import http
from inspection_engine import InspectionEngine

# ── v5.0 Modules ─────────────────────────────────────────────────────────────
from prompt_normalizer import normalize_prompt
from risk_scoring import record_event, get_user_score
from conversation_tracker import tracker as conv_tracker
from quarantine_manager import quarantine

# 1. Initialize the shared CASB Engine
CANARY_TOKEN = os.getenv("CASB_CANARY_TOKEN", "sk-casb-fallback-secret-uuid")
casb_engine = InspectionEngine(CANARY_TOKEN)

# 1.5 OpenRouter Integration
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")

# 2. Splunk HEC Configuration
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
SPLUNK_HEC_URL = "https://localhost:8088/services/collector/event"

def log_to_splunk(event_data: dict):
    """Fire telemetry to Splunk HEC in a background thread to avoid blocking mitmproxy."""
    if not SPLUNK_HEC_TOKEN:
        return
    def _send():
        headers = {"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}", "Content-Type": "application/json"}
        payload = {"sourcetype": "_json", "index": "casb_gateway", "event": event_data}
        try:
            resp = http_requests.post(SPLUNK_HEC_URL, json=payload, headers=headers, timeout=5, verify=False)
            print(f"📡 [SPLUNK] Copilot event logged | HTTP {resp.status_code}")
        except Exception as e:
            print(f"❌ [SPLUNK SEND ERROR]: {e}")
    threading.Thread(target=_send, daemon=True).start()

class CopilotCASB:
    def __init__(self):
        print("🛡️ [CASB Mitmproxy] Interceptor Armed for GitHub Copilot Domains")

    def is_copilot_domain(self, host: str) -> bool:
        """Check if the request is navigating to a known AI assistant API domain."""
        target_domains = [
            "githubcopilot.com", "copilot-proxy.githubusercontent.com", "copilot-telemetry",
            "api.github.com", # Added for Auth Spoofing
            "useblackbox.io", "ai-gateway.vercel.sh", "models.dev", "codegeneration.ai", 
            "openrouter.ai", "blackbox.ai"
        ]
        return any(domain in host for domain in target_domains)

    def request(self, flow: http.HTTPFlow):
        """Intercept outbound requests from VS Code before they reach GitHub."""
        
        # Only scan Copilot chat traffic or auth traffic
        if not self.is_copilot_domain(flow.request.pretty_host):
            return
            
        # ── Auth Hijack (Bypass GitHub Login) ────────────────────────────────
        if "api.github.com" in flow.request.pretty_host and "/copilot_internal/v2/token" in flow.request.pretty_url:
            print("🔓 [CASB HIJACK] Intercepted GitHub Copilot Auth Request. Spoofing token...")
            fake_token_payload = json.dumps({
                "token": "casb-fake-auth-token-1234",
                "expires_at": 2999999999,
                "expires_in": 9999999,
                "refresh_in": 9999999,
                "telemetry": "disabled"
            })
            flow.response = http.Response.make(
                200, fake_token_payload.encode('utf-8'),
                {"Content-Type": "application/json"}
            )
            return
        
        # Only inspect POST requests to chat/completions endpoints
        if flow.request.method != "POST" or "chat/completions" not in flow.request.pretty_url:
            return

        # ── Identity ──────────────────────────────────────────────────────────
        user = flow.request.headers.get("X-User", "copilot_user") # Allow header override, default to copilot_user
        
        # ── SOAR: Check if user is quarantined ────────────────────────────────
        risk_score, risk_level = get_user_score(user)
        soar_action, soar_detail = quarantine.check_and_enforce(
            user, risk_score, risk_level, {"messages": []} # mock data dict
        )
        if soar_action == "quarantined":
            print(f"\n🔒 [SOAR] QUARANTINED: '{user}' (score={risk_score})")
            log_to_splunk({
                "action": "user_quarantined",
                "user": user,
                "risk_score": risk_score,
                "risk_level": risk_level,
            })
            flow.response = http.Response.make(403, soar_detail.encode(), {"Content-Type": "text/plain"})
            return
        elif soar_action == "rate_limited":
            print(f"\n⏱️ [SOAR] RATE LIMITED: '{user}' (score={risk_score})")
            log_to_splunk({
                "action": "user_rate_limited",
                "user": user,
                "risk_score": risk_score,
            })
            flow.response = http.Response.make(429, soar_detail.encode(), {"Content-Type": "text/plain"})
            return
            
        if soar_action == "downgraded":
            print(f"⬇️ [SOAR] Model downgraded for '{user}' (score={risk_score})")

        body = ""
        if flow.request.content:
            try:
                body = flow.request.content.decode('utf-8', errors='ignore')
            except:
                pass
        
        if not body:
            return
        
        # Extract ONLY the user's actual message from the JSON payload
        # Copilot sends: {"messages": [{"role": "system", ...}, {"role": "user", "content": "<context>...</context><reminderInstructions>...</reminderInstructions>\nhi"}]}
        user_message = ""
        try:
            payload = json.loads(body)
            messages = payload.get("messages", [])
            for msg in reversed(messages):
                if msg.get("role") == "user":
                    content = msg.get("content", "")
                    if isinstance(content, list):
                        user_message = " ".join(
                            p.get("text", "") for p in content if isinstance(p, dict)
                        )
                    else:
                        user_message = str(content)
                    break
        except (json.JSONDecodeError, KeyError):
            user_message = body  # Fallback to full body if JSON parsing fails
        
        if not user_message or len(user_message.strip()) < 2:
            return
        
        # Copilot wraps the user's typed input inside a <userRequest> tag.
        # Extract text between <userRequest> and </userRequest> (or end of string).
        scan_input = user_message  # fallback
        user_req_match = re.search(r'<userRequest>\s*(.*?)(?:</userRequest>|$)', user_message, re.DOTALL)
        if user_req_match:
            extracted = user_req_match.group(1).strip()
            if extracted:
                scan_input = extracted
            
        print(f"👉 [CASB] Inspecting Copilot Request to: {flow.request.pretty_url[:70]}...")
        print(f"   📝 User prompt: {scan_input[:800]}...")
            
        # ── LAYER 0: Prompt Normalization (Anti-Evasion) ─────────────────────
        normalized_msg, norm_meta = normalize_prompt(scan_input)
        if norm_meta["evasion_detected"]:
            techniques = ", ".join(norm_meta["evasion_techniques"])
            print(f"\n🛡️ [CASB L0] Evasion attempt detected: [{techniques}] (edit_ratio={norm_meta['edit_distance_ratio']})")
            log_to_splunk({
                "action": "evasion_attempt",
                "user": user,
                "evasion_techniques": techniques,
                "language": norm_meta["language"],
                "edit_distance_ratio": norm_meta["edit_distance_ratio"],
                "original_preview": scan_input[:200],
                "normalized_preview": normalized_msg[:200],
                "severity": "high",
            })
            record_event(user, "evasion_attempt", "high", rule=f"Evasion: {techniques}", layer="L0_Normalizer")
            conv_tracker.record(user, normalized_msg, "evasion_attempt", "high", f"Evasion: {techniques}", "L0_Normalizer")

        # Use normalized version for all inspection from here on
        inspection_input = normalized_msg

        # Layer 1: Entropy (Base64 / Obfuscation)
        # LOG ONLY in forward proxy — Copilot's XML wrapper inflates entropy scores.
        is_suspicious, score, snippet = casb_engine.check_entropy_violations(inspection_input)
        if is_suspicious:
            print(f"⚠️ [CASB L1] FLAG: High Entropy Payload ({score}) from Copilot (log only).")
            record_event(user, "dlp_flagged", "high", rule="High Entropy (Log Only)", layer="L1_Entropy_Analysis")

        # Layer 1.5: Semantic Prompt Injection (DeBERTa)
        # DISABLED in forward proxy: Copilot wraps user input in agent instruction XML
        # that inherently triggers ML injection classifiers. L1.5 is enforced on the
        # LiteLLM reverse proxy where user messages are cleanly isolated.
        # if len(scan_input) > 10:
        #     try:
        #         injection = casb_engine.check_semantic_injection(scan_input[:512])
        #         if injection["blocked"]:
        #             print(f"🚨 [CASB L1.5] BLOCKED: Semantic Injection from Copilot ({injection['injection_score']}).")
        #             flow.response = http.Response.make(403, b"Blocked by AI-CASB: Prompt Injection.", {"Content-Type": "text/plain"})
        #             return
        #     except Exception as e:
        #         print(f"⚠️ [CASB L1.5] Classifier error: {e}")

        # Layer 2: Regex DLP Ingress — on cleaned user input only
        rule = casb_engine.check_dlp_ingress(inspection_input)
        if rule:
            severity = rule.get("severity", "high")
            print(f"🚨 [CASB L2] BLOCKED: Policy violation '{rule['name']}' from Copilot!")
            log_to_splunk({"action": "dlp_block", "layer": "L2_DLP_Regex_Ingress", "rule": rule["name"], "severity": severity, "source": "copilot_forward_proxy", "prompt_preview": scan_input[:800]})
            record_event(user, "dlp_block", severity, rule=rule["name"], layer="L2_DLP_Regex_Ingress")
            conv_tracker.record(user, inspection_input, "dlp_block", severity, rule["name"], "L2_DLP_Regex")
            
            flow.response = http.Response.make(
                403, f"Blocked by AI-CASB: {rule['name']} policy violation.".encode(),
                {"Content-Type": "text/plain"}
            )
            return

        # ── Record benign event in conversation tracker ───────────────────────
        conv_tracker.record(user, inspection_input, "ai_inference", "none", "", "")

        # ── Multi-Turn Pattern Detection ─────────────────────────────────────
        pattern = conv_tracker.detect_patterns(user)
        if pattern:
            print(f"\n🔍 [CASB MULTI-TURN] Pattern detected: {pattern['pattern']} for '{user}'")
            log_to_splunk({
                "action": "multi_turn_pattern",
                "user": user,
                "pattern_type": pattern["pattern"],
                "pattern_description": pattern["description"],
                "mitre_attack": ", ".join(pattern.get("mitre_attack", [])),
                "mitre_atlas": ", ".join(pattern.get("mitre_atlas", [])),
                "severity": "high",
            })
            # Boost risk score for multi-turn patterns
            record_event(user, "dlp_flagged", "high", rule=f"Multi-Turn: {pattern['pattern']}", layer="Conv_Tracker")

        # ── HIJACK: Reroute to OpenRouter ────────────────────────────────────
        print("🔀 [CASB HIJACK] Rerouting request from GitHub Copilot to OpenRouter (Llama 3 8B)")
        flow.request.scheme = "https"
        flow.request.host = "openrouter.ai"
        flow.request.port = 443
        flow.request.path = "/api/v1/chat/completions"

        # Update headers
        flow.request.headers["Host"] = "openrouter.ai"
        flow.request.headers["Authorization"] = f"Bearer {OPENROUTER_API_KEY}"
        flow.request.headers["HTTP-Referer"] = "https://ai-casb.local"
        flow.request.headers["X-Title"] = "AI-CASB Copilot Hijacker"
        
        # Strip Copilot-specific headers that might confuse OpenRouter
        for h in ["github-authentication-token", "vscode-sessionid", "vscode-machineid", "authorization"]:
            if h in flow.request.headers:
                del flow.request.headers[h]

        # Rewrite payload for OpenRouter
        try:
            original_payload = json.loads(body)
            # Reconstruct standard OpenAI payload
            new_payload = {
                "model": "meta-llama/llama-3-8b-instruct:free",
                "messages": original_payload.get("messages", [{"role": "user", "content": scan_input}]),
                "stream": original_payload.get("stream", True)
            }
            flow.request.content = json.dumps(new_payload).encode('utf-8')
        except Exception as e:
            print(f"⚠️ [CASB HIJACK] Failed to rewrite body: {e}")

    def response(self, flow: http.HTTPFlow):
        """Intercept inbound responses from GitHub Copilot before they reach VS Code."""
        if not self.is_copilot_domain(flow.request.pretty_host):
            return

        user = "copilot_user" # Match the ingress request user

        body = ""
        if flow.response and flow.response.content:
            try:
                body = flow.response.content.decode('utf-8', errors='ignore')
            except:
                pass
        
        if not body:
            return

        # For SSE streams, extract the actual text content from the data: lines
        scan_text = body
        content_type = flow.response.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            extracted_parts = []
            for line in body.split('\n'):
                line = line.strip()
                if line.startswith('data: ') and not line.startswith('data: [DONE]'):
                    json_str = line[6:]
                    try:
                        chunk = json.loads(json_str)
                        # OpenAI-style SSE: choices[0].delta.content
                        choices = chunk.get("choices", [])
                        for choice in choices:
                            delta = choice.get("delta", {})
                            content = delta.get("content", "")
                            if content:
                                extracted_parts.append(content)
                    except (json.JSONDecodeError, KeyError):
                        pass
            if extracted_parts:
                scan_text = "".join(extracted_parts)
                print(f"📝 [CASB] Extracted {len(scan_text)} chars from SSE stream for DLP scan.")

        # Layer 3: Canary Token Exfiltration
        if CANARY_TOKEN in scan_text:
            print("\n🚨🚨 [CASB L3 CRITICAL] CANARY TOKEN EXFILTRATED IN RESPONSE!")
            log_to_splunk({"action": "dlp_block", "layer": "L3_Canary_Token", "rule": "Canary Token Exfiltration", "severity": "critical", "source": "copilot_forward_proxy", "prompt_preview": f"[AI RESPONSE BLOCKED] {scan_text[:800]}"})
            record_event(user, "intrusion_detected", "critical", rule="Canary Token Exfiltration", layer="L3_Canary_Honeypot")
            flow.response.content = b'CASB Critical: Honeypot exfiltrated. Modifying response.'
            flow.response.status_code = 403
            return

        # Layer 3: Egress DLP — SURGICAL REDACTION MODE
        # Instead of a hard 403 block, we redact ALL secrets in-place and let the
        # response through. The developer gets Copilot's guidance; secrets stay hidden.
        rule, _matched = casb_engine.check_dlp_egress(scan_text)
        if rule:
            # Run redact_dlp_egress to replace ALL matched secrets in the full raw body
            redacted_body, violated_rules = casb_engine.redact_dlp_egress(body)
            rule_names = ", ".join(r["name"] for r in violated_rules)
            print(f"\n✂️ [CASB L3 REDACT] Surgical redaction applied: {rule_names}")
            log_to_splunk({
                "action": "dlp_redact",
                "layer": "L3_DLP_Regex_Egress",
                "rule": rule_names,
                "severity": "high",
                "source": "copilot_forward_proxy",
                "prompt_preview": f"[AI RESPONSE REDACTED - {rule_names}] Original: {scan_text[:800]}"
            })
            record_event(user, "egress_flagged", "high", rule=rule_names, layer="L3_DLP_Regex_Egress")
            # Replace the response body with the redacted version
            flow.response.content = redacted_body.encode('utf-8', errors='replace')
            return


    def responseheaders(self, flow: http.HTTPFlow):
        """Buffer Server-Sent Events (SSE) streaming responses for complete content inspection."""
        if not self.is_copilot_domain(flow.request.pretty_host):
            return
            
        content_type = flow.response.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            # Force mitmproxy to buffer the entire stream instead of streaming it chunks to the client.
            # This allows the `response` hook below to analyze the entire assembled payload at once.
            flow.response.stream = False

    def websocket_message(self, flow: http.HTTPFlow):
        """Intercept WebSocket traffic (used by Blackbox AI and other streaming extensions)."""
        if not self.is_copilot_domain(flow.request.pretty_host):
            return

        message = flow.websocket.messages[-1]
        body = ""
        try:
            if isinstance(message.content, bytes):
                body = message.content.decode('utf-8', errors='ignore')
            else:
                body = str(message.content)
        except:
            pass

        if not body:
            return

        if message.from_client:
            # Client sent message (Ingress)
            is_suspicious, score, snippet = casb_engine.check_entropy_violations(body)
            if is_suspicious:
                 print(f"🚨 [CASB WS L1] BLOCKED: High Entropy ({score}).")
                 message.drop()
                 return
                 
            injection = casb_engine.check_semantic_injection(body[-1024:])
            if injection["blocked"]:
                 print(f"🚨 [CASB WS L1.5] BLOCKED: Semantic Injection detected!")
                 message.drop()
                 return

            rule = casb_engine.check_dlp_ingress(body)
            if rule:
                 print(f"\n🚨 [CASB WS L2] BLOCKED: {rule['name']} - WebSocket")
                 message.drop()
                 return
        else:
            # Server sent message (Egress)
            if CANARY_TOKEN in body:
                 print("\n🚨🚨 [CASB WS L3 CRITICAL] CANARY EXFILTRATED!")
                 message.content = b'CASB Blocked: Honeypot Exfiltrated.' if isinstance(message.content, bytes) else 'CASB Blocked: Honeypot Exfiltrated.'
                 return

            rule = casb_engine.check_dlp_egress(body)
            if rule:
                 print(f"\n🚨 [CASB WS L3 EGRESS] Blocked streaming response: {rule['name']}")
                 message.content = f'CASB Blocked: {rule["name"]} detected in stream.'.encode() if isinstance(message.content, bytes) else f'CASB Blocked: {rule["name"]} detected in stream.'
                 return


addons = [
    CopilotCASB()
]
