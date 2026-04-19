import os
import re
import json
import threading
import requests as http_requests
from mitmproxy import http
from inspection_engine import InspectionEngine

# 1. Initialize the shared CASB Engine
CANARY_TOKEN = os.getenv("CASB_CANARY_TOKEN", "")
casb_engine = InspectionEngine(CANARY_TOKEN)

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
            splunk_ca = os.getenv("SPLUNK_CA_CERT", False)  # Set to CA cert path in production, False only for local dev
            resp = http_requests.post(SPLUNK_HEC_URL, json=payload, headers=headers, timeout=5, verify=splunk_ca)
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
            "useblackbox.io", "ai-gateway.vercel.sh", "models.dev", "codegeneration.ai", 
            "openrouter.ai", "blackbox.ai"
        ]
        return any(domain in host for domain in target_domains)

    def request(self, flow: http.HTTPFlow):
        """Intercept outbound requests from VS Code before they reach GitHub."""
        
        # Only scan Copilot chat traffic, not telemetry or model listing
        if not self.is_copilot_domain(flow.request.pretty_host):
            return
        
        # Only inspect POST requests to chat/completions endpoints
        if flow.request.method != "POST" or "chat/completions" not in flow.request.pretty_url:
            return

        body = ""
        if flow.request.content:
            try:
                body = flow.request.content.decode('utf-8', errors='ignore')
            except Exception:
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
            
        # Layer 1: Entropy (Base64 / Obfuscation)
        # LOG ONLY in forward proxy — Copilot's XML wrapper inflates entropy scores.
        is_suspicious, score, snippet = casb_engine.check_entropy_violations(scan_input)
        if is_suspicious:
            print(f"⚠️ [CASB L1] FLAG: High Entropy Payload ({score}) from Copilot (log only).")

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
        rule = casb_engine.check_dlp_ingress(scan_input)
        if rule:
            print(f"🚨 [CASB L2] BLOCKED: Policy violation '{rule['name']}' from Copilot!")
            log_to_splunk({"action": "dlp_block", "layer": "L2_DLP_Regex_Ingress", "rule": rule["name"], "severity": rule.get("severity", "high"), "source": "copilot_forward_proxy", "prompt_preview": scan_input[:800]})
            flow.response = http.Response.make(
                403, f"Blocked by AI-CASB: {rule['name']} policy violation.".encode(),
                {"Content-Type": "text/plain"}
            )
            return

    def response(self, flow: http.HTTPFlow):
        """Intercept inbound responses from GitHub Copilot before they reach VS Code."""
        if not self.is_copilot_domain(flow.request.pretty_host):
            return

        body = ""
        if flow.response and flow.response.content:
            try:
                body = flow.response.content.decode('utf-8', errors='ignore')
            except Exception:
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
