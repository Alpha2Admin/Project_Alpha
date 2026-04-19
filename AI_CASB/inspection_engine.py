import os
import json
import re
import math
from prompt_classifier import classify_prompt

RULES_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dlp_rules.json")

class InspectionEngine:
    """
    Centralized Inspection Engine for the AI-CASB.
    Performs Entropy analysis, Semantic classification, and DLP Regex matching.
    Designed to be used across different proxy variants (LiteLLM and mitmproxy).
    """
    def __init__(self, canary_token: str):
        self.canary_token = canary_token
        self._rules_cache = []
        self._rules_mtime = 0
        self.entropy_block_threshold = 4.8
        self.entropy_min_scan_length = 50

    def load_dlp_rules(self):
        """Load DLP rules from JSON file. Hot-reloads automatically when the file changes."""
        try:
            current_mtime = os.path.getmtime(RULES_FILE)
            if current_mtime != self._rules_mtime:
                with open(RULES_FILE, "r") as f:
                    raw_rules = f.read()
                    # Dynamically inject the canary token into the rules so it's not hardcoded
                    raw_rules = raw_rules.replace("CASB_CANARY_TOKEN_PLACEHOLDER", self.canary_token)
                    self._rules_cache = json.loads(raw_rules)
                self._rules_mtime = current_mtime
                print(f"🔄 [CASB Engine] Reloaded {len(self._rules_cache)} DLP rules from {RULES_FILE}")
        except Exception as e:
            print(f"❌ [CASB Engine] Failed to load DLP rules: {e}")
        return self._rules_cache

    def compute_shannon_entropy(self, text: str) -> float:
        """Compute Shannon entropy of a string."""
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

    def check_entropy_violations(self, text: str) -> tuple:
        """
        Scan text for high-entropy obfuscated payloads.
        Returns (is_suspicious: bool, max_entropy_score: float, offending_snippet: str)
        """
        words = text.split()

        # Check individual long tokens
        for word in words:
            if len(word) >= self.entropy_min_scan_length:
                score = self.compute_shannon_entropy(word)
                if score >= self.entropy_block_threshold:
                    return True, round(score, 2), word[:80]

        # Sliding window check across the full text
        if len(text) >= self.entropy_min_scan_length:
            for i in range(0, len(text) - 60, 40):
                chunk = text[i:i + 80]
                if len(chunk) >= self.entropy_min_scan_length:
                    score = self.compute_shannon_entropy(chunk)
                    if score >= self.entropy_block_threshold:
                        return True, round(score, 2), chunk[:80]

        return False, 0.0, ""

    def check_semantic_injection(self, text: str) -> dict:
        """
        Run text through the DeBERTa model for Prompt Injection prediction.
        """
        classifier_input = text[:512]
        if classifier_input and len(classifier_input) > 10:
            return classify_prompt(classifier_input)
        return {"blocked": False, "label": "safe", "injection_score": 0.0, "safe_score": 1.0, "latency_ms": 0}

    def check_dlp_ingress(self, text: str) -> dict:
        """
        Run ingress regex rules against the text.
        Returns a dict describing the violation if found, or None if safe.
        """
        rules = self.load_dlp_rules()
        for rule in rules:
            if not rule.get("enabled", True):
                continue
            if rule.get("scope", "both") == "egress":
                continue
            if re.search(rule["pattern"], text):
                return rule
        return None

    def check_dlp_egress(self, text: str):
        """
        Run egress regex rules against the text.
        Returns (rule_dict, matched_string) if a violation is found, or (None, None) if safe.
        """
        rules = self.load_dlp_rules()
        for rule in rules:
            if not rule.get("enabled", True):
                continue
            if rule.get("scope", "both") == "ingress":
                continue
            match = re.search(rule["pattern"], text)
            if match:
                return rule, match.group(0)
        return None, None

    def redact_dlp_egress(self, text: str) -> tuple:
        """
        Scan text for ALL egress DLP violations and redact them in-place.
        Returns (redacted_text, list_of_violated_rules).
        Unlike check_dlp_egress, this does NOT stop at the first match.
        """
        rules = self.load_dlp_rules()
        violated = []
        redacted = text
        for rule in rules:
            if not rule.get("enabled", True):
                continue
            if rule.get("scope", "both") == "ingress":
                continue
            new_text, count = re.subn(
                rule["pattern"],
                f"[REDACTED:{rule['name']}]",
                redacted
            )
            if count > 0:
                violated.append(rule)
                redacted = new_text
        return redacted, violated
