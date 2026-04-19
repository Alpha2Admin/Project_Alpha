"""
AI-CASB v5.0 — Persistent Risk Scoring Engine
===============================================
SQLite-backed per-user risk scoring with time-decay.

Risk Points:
  Benign prompt       →  0 pts
  DLP Flagged (high)  → +2 pts   (decay -0.5/hour)
  DLP Flagged (medium)→ +1 pt    (decay -0.3/hour)
  DLP Blocked         → +10 pts  (decay -1/hour)
  Egress violation    → +15 pts  (decay -1/hour)

Thresholds:
   0–10  → 🟢 Normal
  11–25  → 🟡 Elevated  (logged to Splunk)
  26–50  → 🟠 High      (Splunk behavioral alert → IRIS)
  50+    → 🔴 Critical  (auto-quarantine)

RAM Impact: ~5 MB (SQLite in-process)
"""

import os
import time
import sqlite3
import threading
from typing import Optional, Tuple

DB_PATH = os.getenv("CASB_RISK_DB", "/tmp/casb_risk_scores.db")
_local = threading.local()

# ── Risk Point Map ───────────────────────────────────────────────────────────
RISK_POINTS = {
    # (action, severity) → points
    ("dlp_block", "critical"):   10,
    ("dlp_block", "high"):       10,
    ("dlp_monitor", "critical"): 8,
    ("dlp_flagged", "high"):     2,
    ("dlp_flagged", "medium"):   1,
    ("dlp_flagged", "low"):      0.5,
    ("egress_block", "critical"):15,
    ("egress_block", "high"):    10,
    ("egress_flagged", "high"):  3,
    ("egress_flagged", "medium"):2,
    ("intrusion_detected", "critical"): 50,
    ("evasion_attempt", "high"): 5,
}

# Points decay rate per hour
DECAY_RATES = {
    "critical": 1.0,
    "high":     0.5,
    "medium":   0.3,
    "low":      0.1,
}

# Thresholds
THRESHOLD_ELEVATED = 11
THRESHOLD_HIGH     = 26
THRESHOLD_CRITICAL = 50


def _get_conn() -> sqlite3.Connection:
    """Get thread-local SQLite connection."""
    if not hasattr(_local, 'conn') or _local.conn is None:
        _local.conn = sqlite3.connect(DB_PATH, timeout=5)
        _local.conn.execute("PRAGMA journal_mode=WAL")
        _init_db(_local.conn)
    return _local.conn


def _init_db(conn: sqlite3.Connection):
    """Create tables if they don't exist."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            user_id     TEXT PRIMARY KEY,
            risk_score  REAL DEFAULT 0.0,
            risk_level  TEXT DEFAULT 'normal',
            first_seen  TEXT,
            last_seen   TEXT,
            total_events INTEGER DEFAULT 0,
            total_blocks INTEGER DEFAULT 0,
            total_flags  INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS risk_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     TEXT NOT NULL,
            timestamp   REAL NOT NULL,
            action      TEXT NOT NULL,
            severity    TEXT NOT NULL,
            points      REAL NOT NULL,
            rule        TEXT,
            layer       TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_user ON risk_events(user_id);
        CREATE INDEX IF NOT EXISTS idx_events_time ON risk_events(timestamp);
    """)
    conn.commit()


def record_event(user_id: str, action: str, severity: str,
                 rule: str = "", layer: str = "") -> Tuple[float, str]:
    """
    Record a security event and return the updated (risk_score, risk_level).
    """
    conn = _get_conn()
    now = time.time()
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Calculate points for this event
    points = RISK_POINTS.get((action, severity), 0)
    if points == 0:
        # Try action-only fallback
        for (a, s), p in RISK_POINTS.items():
            if a == action:
                points = p
                break

    # Insert event
    conn.execute(
        "INSERT INTO risk_events (user_id, timestamp, action, severity, points, rule, layer) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, now, action, severity, points, rule, layer)
    )

    # Upsert user
    conn.execute("""
        INSERT INTO users (user_id, risk_score, first_seen, last_seen, total_events, total_blocks, total_flags)
        VALUES (?, 0, ?, ?, 1, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            last_seen = ?,
            total_events = total_events + 1,
            total_blocks = total_blocks + ?,
            total_flags = total_flags + ?
    """, (
        user_id, now_iso, now_iso,
        1 if 'block' in action else 0,
        1 if 'flag' in action else 0,
        now_iso,
        1 if 'block' in action else 0,
        1 if 'flag' in action else 0,
    ))

    # Calculate current score with decay
    score = _calculate_score(conn, user_id, now)

    # Determine risk level
    if score >= THRESHOLD_CRITICAL:
        level = "critical"
    elif score >= THRESHOLD_HIGH:
        level = "high"
    elif score >= THRESHOLD_ELEVATED:
        level = "elevated"
    else:
        level = "normal"

    # Update user record
    conn.execute(
        "UPDATE users SET risk_score = ?, risk_level = ? WHERE user_id = ?",
        (round(score, 2), level, user_id)
    )
    conn.commit()

    return round(score, 2), level


def _calculate_score(conn: sqlite3.Connection, user_id: str, now: float) -> float:
    """Calculate risk score with time decay for all events in the last 24 hours."""
    cursor = conn.execute(
        "SELECT timestamp, points, severity FROM risk_events "
        "WHERE user_id = ? AND timestamp > ? ORDER BY timestamp DESC",
        (user_id, now - 86400)  # Last 24 hours
    )
    total = 0.0
    for ts, pts, sev in cursor:
        age_hours = (now - ts) / 3600.0
        decay_rate = DECAY_RATES.get(sev, 0.3)
        decayed = max(0, pts - (decay_rate * age_hours))
        total += decayed
    return total


def get_user_score(user_id: str) -> Tuple[float, str]:
    """Get the current risk score and level for a user."""
    conn = _get_conn()
    now = time.time()
    score = _calculate_score(conn, user_id, now)

    if score >= THRESHOLD_CRITICAL:
        level = "critical"
    elif score >= THRESHOLD_HIGH:
        level = "high"
    elif score >= THRESHOLD_ELEVATED:
        level = "elevated"
    else:
        level = "normal"

    return round(score, 2), level


def get_top_users(limit: int = 10) -> list:
    """Get top N riskiest users. Used by the compliance dashboard."""
    conn = _get_conn()
    now = time.time()

    cursor = conn.execute("SELECT user_id FROM users ORDER BY risk_score DESC LIMIT ?", (limit,))
    results = []
    for (uid,) in cursor:
        score, level = get_user_score(uid)
        user_row = conn.execute(
            "SELECT first_seen, last_seen, total_events, total_blocks, total_flags "
            "FROM users WHERE user_id = ?", (uid,)
        ).fetchone()
        if user_row:
            results.append({
                "user_id": uid,
                "risk_score": score,
                "risk_level": level,
                "first_seen": user_row[0],
                "last_seen": user_row[1],
                "total_events": user_row[2],
                "total_blocks": user_row[3],
                "total_flags": user_row[4],
            })
    return results


def is_quarantined(user_id: str) -> bool:
    """Check if user's score is above the critical threshold."""
    score, level = get_user_score(user_id)
    return level == "critical"
