"""
AI-CASB v5.0 — Quarantine Manager (SOAR Lite)
===============================================
Automated response actions triggered by risk thresholds.

Actions:
  🟡 Elevated (11–25) → Model downgrade (GPT-4 → GPT-3.5)
  🟠 High (26–50)     → Rate limiting (5 req/min)
  🔴 Critical (50+)   → Full quarantine (HTTP 403)

RAM Impact: ~0 MB
"""

import time
from collections import defaultdict
from typing import Optional, Tuple

# ── Rate Limiter (Token Bucket) ──────────────────────────────────────────────
class TokenBucket:
    """Simple token bucket rate limiter."""
    def __init__(self, rate: float = 5.0, capacity: float = 5.0):
        self.rate = rate           # tokens per minute
        self.capacity = capacity   # max burst
        self.tokens = capacity
        self.last_check = time.time()

    def consume(self) -> bool:
        """Try to consume a token. Returns True if allowed, False if rate limited."""
        now = time.time()
        elapsed = now - self.last_check
        self.last_check = now
        self.tokens = min(self.capacity, self.tokens + self.rate * (elapsed / 60.0))

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


class QuarantineManager:
    """Manages automated response actions based on user risk levels."""

    def __init__(self):
        self._quarantined: set = set()           # Fully blocked users
        self._rate_limiters: dict = {}            # user_id → TokenBucket
        self._downgraded: set = set()             # Users forced to weaker models
        self._action_log: list = []               # Audit trail

    def check_and_enforce(self, user_id: str, risk_score: float,
                          risk_level: str, kwargs: dict) -> Tuple[str, Optional[str]]:
        """
        Check the user's risk level and enforce the appropriate response action.

        Returns:
          (action_taken, detail_message)
          action_taken: "allowed" | "downgraded" | "rate_limited" | "quarantined"
          detail_message: Human-readable explanation (or None if allowed)
        """
        # ── Critical: Full Quarantine ────────────────────────────────────────
        if risk_level == "critical" or user_id in self._quarantined:
            if user_id not in self._quarantined:
                self._quarantined.add(user_id)
                self._action_log.append({
                    "timestamp": time.time(),
                    "user_id": user_id,
                    "action": "quarantine",
                    "risk_score": risk_score,
                })
            return "quarantined", (
                f"Account suspended: Your access has been temporarily revoked due to repeated "
                f"security policy violations (risk score: {risk_score}). "
                f"Contact your security administrator."
            )

        # ── High: Rate Limiting ──────────────────────────────────────────────
        if risk_level == "high":
            if user_id not in self._rate_limiters:
                self._rate_limiters[user_id] = TokenBucket(rate=5.0, capacity=5.0)
                self._action_log.append({
                    "timestamp": time.time(),
                    "user_id": user_id,
                    "action": "rate_limit_applied",
                    "risk_score": risk_score,
                })

            bucket = self._rate_limiters[user_id]
            if not bucket.consume():
                return "rate_limited", (
                    f"Rate limit exceeded: Your account has been throttled due to elevated risk "
                    f"activity (risk score: {risk_score}). Please wait before trying again."
                )

            # Also downgrade the model
            if "model" in kwargs:
                original_model = kwargs["model"]
                kwargs["model"] = "gpt-3.5-turbo"
                if user_id not in self._downgraded:
                    self._downgraded.add(user_id)
                    self._action_log.append({
                        "timestamp": time.time(),
                        "user_id": user_id,
                        "action": "model_downgrade",
                        "original_model": original_model,
                        "forced_model": "gpt-3.5-turbo",
                        "risk_score": risk_score,
                    })

            return "allowed", None  # Allowed but rate-limited + downgraded

        # ── Elevated: Model Downgrade Only ───────────────────────────────────
        if risk_level == "elevated":
            if "model" in kwargs:
                original_model = kwargs["model"]
                kwargs["model"] = "gpt-3.5-turbo"
                if user_id not in self._downgraded:
                    self._downgraded.add(user_id)
                    self._action_log.append({
                        "timestamp": time.time(),
                        "user_id": user_id,
                        "action": "model_downgrade",
                        "original_model": original_model,
                        "forced_model": "gpt-3.5-turbo",
                        "risk_score": risk_score,
                    })

            return "allowed", None

        # ── Normal: No action ────────────────────────────────────────────────
        return "allowed", None

    def unblock_user(self, user_id: str) -> bool:
        """Remove a user from quarantine (called by analyst via IRIS/API)."""
        was_blocked = user_id in self._quarantined
        self._quarantined.discard(user_id)
        self._downgraded.discard(user_id)
        self._rate_limiters.pop(user_id, None)
        if was_blocked:
            self._action_log.append({
                "timestamp": time.time(),
                "user_id": user_id,
                "action": "unblocked",
            })
        return was_blocked

    def get_quarantined_users(self) -> list:
        """List all quarantined users."""
        return list(self._quarantined)

    def get_audit_log(self, limit: int = 50) -> list:
        """Get recent SOAR action log entries."""
        return self._action_log[-limit:]


# Singleton instance
quarantine = QuarantineManager()
