"""
AI-CASB v3.0 — Semantic Prompt Injection Classifier
====================================================

Uses ProtectAI's DeBERTa-v3-base model (86M params, ~350MB) as a deterministic
binary classifier for prompt injection detection.

This module is NOT a generative model — it cannot be socially engineered.
It performs a single mathematical forward pass and outputs a probability
score between 0.0 (safe) and 1.0 (injection). That's it.

Model: protectai/deberta-v3-base-prompt-injection-v2
License: Apache 2.0
"""

import os
import time
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# ── Configuration ────────────────────────────────────────────────────────────
MODEL_NAME = "protectai/deberta-v3-base-prompt-injection-v2"
INJECTION_THRESHOLD = 0.85  # Block if injection confidence > 85%
MAX_INPUT_LENGTH = 512      # DeBERTa max token window

# ── Singleton Loader ─────────────────────────────────────────────────────────
_tokenizer = None
_model = None
_device = None
_loaded = False


def _load_model():
    """
    Lazily load the model into memory on first use.
    Runs on CPU by default — at 86M params this classifies in <15ms on CPU.
    """
    global _tokenizer, _model, _device, _loaded

    if _loaded:
        return

    print("🧠 [CASB L1.5] Loading semantic classifier: protectai/deberta-v3-base-prompt-injection-v2...")
    start = time.time()

    _device = torch.device("cpu")  # CPU is faster for single-inference on small models
    _tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
    _model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
    _model.to(_device)
    _model.eval()  # Lock into inference mode (no gradient computation)

    elapsed = round(time.time() - start, 2)
    print(f"✅ [CASB L1.5] Semantic classifier loaded in {elapsed}s — {sum(p.numel() for p in _model.parameters()) / 1e6:.1f}M params")
    _loaded = True


def classify_prompt(text: str) -> dict:
    """
    Classify a prompt as SAFE or INJECTION.

    Returns:
        {
            "label": "INJECTION" or "SAFE",
            "injection_score": float (0.0 to 1.0),
            "safe_score": float (0.0 to 1.0),
            "latency_ms": float,
            "blocked": bool
        }
    """
    _load_model()

    start = time.time()

    # Tokenize with truncation (DeBERTa has a 512 token window)
    inputs = _tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        max_length=MAX_INPUT_LENGTH,
        padding=True
    ).to(_device)

    # Forward pass — no gradients needed (pure inference)
    with torch.no_grad():
        outputs = _model(**inputs)
        probabilities = torch.softmax(outputs.logits, dim=-1)

    # Extract scores — label mapping: 0=SAFE, 1=INJECTION
    safe_score = probabilities[0][0].item()
    injection_score = probabilities[0][1].item()
    latency_ms = round((time.time() - start) * 1000, 2)

    label = "INJECTION" if injection_score >= INJECTION_THRESHOLD else "SAFE"
    blocked = injection_score >= INJECTION_THRESHOLD

    return {
        "label": label,
        "injection_score": round(injection_score, 4),
        "safe_score": round(safe_score, 4),
        "latency_ms": latency_ms,
        "blocked": blocked
    }


# ── Pre-warm on import (optional, makes first request faster) ────────────────
def warmup():
    """Pre-load the model so the first real request doesn't pay the cold-start penalty."""
    _load_model()
    # Run a dummy classification to warm PyTorch JIT
    classify_prompt("Hello, how are you?")
    print("🔥 [CASB L1.5] Semantic classifier warmed up and ready.")
