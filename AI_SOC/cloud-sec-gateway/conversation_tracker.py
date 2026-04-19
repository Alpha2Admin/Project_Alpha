"""
AI-CASB v5.0 — Conversation Tracker
=====================================
Tracks per-user conversation history to detect multi-turn attack patterns.

Detections:
  1. Intent Escalation:  benign → flagged → blocked across turns
  2. Topic Pivot:        sudden shift from safe to sensitive topics
  3. Persistence:        repeated blocked categories across sessions

RAM Impact: ~10 MB (LRU cache, max 1000 users × 20 messages)
"""

import time
from collections import OrderedDict
from typing import Optional

MAX_USERS = 1000
MAX_MESSAGES_PER_USER = 20


class ConversationTracker:
    """LRU cache-based conversation tracker with pattern detection."""

    def __init__(self, max_users: int = MAX_USERS, max_msgs: int = MAX_MESSAGES_PER_USER):
        self._cache: OrderedDict = OrderedDict()
        self._max_users = max_users
        self._max_msgs = max_msgs

    def record(self, user_id: str, prompt_preview: str, action: str,
               severity: str, rule: str, layer: str):
        """Record a prompt event for a user."""
        entry = {
            "prompt": prompt_preview[:200],
            "timestamp": time.time(),
            "action": action,
            "severity": severity,
            "rule": rule,
            "layer": layer,
        }

        if user_id in self._cache:
            # Move to end (most recently used)
            self._cache.move_to_end(user_id)
            self._cache[user_id].append(entry)
            # Trim to max messages
            if len(self._cache[user_id]) > self._max_msgs:
                self._cache[user_id] = self._cache[user_id][-self._max_msgs:]
        else:
            # Evict least recently used if full
            if len(self._cache) >= self._max_users:
                self._cache.popitem(last=False)
            self._cache[user_id] = [entry]

    def detect_patterns(self, user_id: str) -> Optional[dict]:
        """
        Analyze a user's conversation history for multi-turn attack patterns.
        Returns a dict with pattern info if detected, or None.
        """
        if user_id not in self._cache:
            return None

        history = self._cache[user_id]
        if len(history) < 3:
            return None

        # Only consider recent messages (last 15 minutes)
        now = time.time()
        recent = [h for h in history if now - h["timestamp"] < 900]

        if len(recent) < 3:
            return None

        # ── Pattern 1: Intent Escalation ─────────────────────────────────────
        # Check if severity is escalating across the last N messages
        severity_scores = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        action_scores = {"ai_inference": 0, "dlp_flagged": 2, "dlp_block": 4, "egress_block": 5}

        escalation_score = 0
        for i in range(1, len(recent)):
            prev_sev = severity_scores.get(recent[i-1].get("severity", ""), 0)
            curr_sev = severity_scores.get(recent[i].get("severity", ""), 0)
            prev_act = action_scores.get(recent[i-1].get("action", ""), 0)
            curr_act = action_scores.get(recent[i].get("action", ""), 0)

            if curr_sev > prev_sev or curr_act > prev_act:
                escalation_score += 1

        # If 3+ consecutive escalations in recent history
        if escalation_score >= 3:
            return {
                "pattern": "intent_escalation",
                "description": f"User '{user_id}' showed escalating threat severity across {len(recent)} recent messages",
                "message_count": len(recent),
                "escalation_steps": escalation_score,
                "mitre_attack": ["T1190", "T1078"],
                "mitre_atlas": ["AML.T0051", "AML.T0040"],
            }

        # ── Pattern 2: Topic Pivot ───────────────────────────────────────────
        # First N messages are benign (ai_inference), then suddenly flagged/blocked
        benign_count = 0
        hostile_count = 0
        pivot_found = False

        for entry in recent:
            if entry["action"] in ("ai_inference",):
                if hostile_count > 0:
                    break  # Already past the pivot
                benign_count += 1
            elif entry["action"] in ("dlp_flagged", "dlp_block", "egress_block"):
                if benign_count >= 2:
                    pivot_found = True
                hostile_count += 1

        if pivot_found and benign_count >= 2 and hostile_count >= 2:
            return {
                "pattern": "topic_pivot",
                "description": f"User '{user_id}' pivoted from {benign_count} benign to {hostile_count} hostile prompts",
                "benign_count": benign_count,
                "hostile_count": hostile_count,
                "mitre_attack": ["T1078", "T1204"],
                "mitre_atlas": ["AML.T0040", "AML.T0043"],
            }

        # ── Pattern 3: Persistence ───────────────────────────────────────────
        # Same rule triggered 3+ times across messages (attacker keeps trying)
        rule_counts = {}
        for entry in recent:
            if entry["action"] in ("dlp_block", "dlp_flagged"):
                r = entry.get("rule", "unknown")
                rule_counts[r] = rule_counts.get(r, 0) + 1

        for rule_name, count in rule_counts.items():
            if count >= 3:
                return {
                    "pattern": "persistence",
                    "description": f"User '{user_id}' triggered '{rule_name}' {count} times in recent history",
                    "rule": rule_name,
                    "repeat_count": count,
                    "mitre_attack": ["T1190"],
                    "mitre_atlas": ["AML.T0051", "AML.T0054"],
                }

        return None

    def get_user_history(self, user_id: str) -> list:
        """Get conversation history for a user (for compliance/forensics)."""
        return list(self._cache.get(user_id, []))


# Singleton instance
tracker = ConversationTracker()
