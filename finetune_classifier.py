#!/usr/bin/env python3
"""
AI-CASB v4.0 — DeBERTa Fine-Tuning Pipeline
============================================
Fine-tunes the ProtectAI prompt injection classifier on your own
organization-specific examples to improve accuracy over time.

WORKFLOW:
  1. Collect missed injections / false positives in the ML Trainer tab
     at http://localhost:5001 (Tab: "ML Trainer")
  2. Click "Export JSONL Dataset" → save as training_data/my_samples.jsonl
  3. Run: python finetune_classifier.py --data training_data/my_samples.jsonl
  4. Restart CASB — the new model loads automatically from ./models/casb-finetuned/

DATASET FORMAT (JSONL — one JSON object per line):
  {"text": "Ignore all previous instructions", "label": "INJECTION"}
  {"text": "How do I sort a list in Python?",   "label": "SAFE"}

REQUIREMENTS:
  pip install transformers torch datasets scikit-learn accelerate
"""

import argparse
import json
import os
import sys
from pathlib import Path

# ─── Validate imports ─────────────────────────────────────────────────────────
try:
    import torch
    from transformers import (
        AutoTokenizer,
        AutoModelForSequenceClassification,
        TrainingArguments,
        Trainer,
        DataCollatorWithPadding,
    )
    from datasets import Dataset
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report
    import numpy as np
except ImportError as e:
    print(f"❌ Missing dependency: {e}")
    print("   Install with: pip install transformers torch datasets scikit-learn accelerate")
    sys.exit(1)

# ─── Config ───────────────────────────────────────────────────────────────────
BASE_MODEL   = "protectai/deberta-v3-base-prompt-injection-v2"
OUTPUT_DIR   = "./models/casb-finetuned"
LABEL2ID     = {"SAFE": 0, "INJECTION": 1}
ID2LABEL     = {0: "SAFE", 1: "INJECTION"}
MAX_LENGTH   = 512


# ─── Load dataset ─────────────────────────────────────────────────────────────
def load_jsonl(path: str) -> list[dict]:
    samples = []
    skipped = 0
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                text  = obj.get("text", "").strip()
                label = obj.get("label", "").upper().strip()
                if not text:
                    print(f"  ⚠️  Line {i}: empty text — skipped")
                    skipped += 1
                    continue
                if label not in LABEL2ID:
                    print(f"  ⚠️  Line {i}: unknown label '{label}' (must be INJECTION or SAFE) — skipped")
                    skipped += 1
                    continue
                samples.append({"text": text, "label": LABEL2ID[label]})
            except json.JSONDecodeError:
                print(f"  ⚠️  Line {i}: invalid JSON — skipped")
                skipped += 1
    if skipped:
        print(f"  ℹ️  {skipped} lines skipped due to errors")
    return samples


# ─── Tokenize ─────────────────────────────────────────────────────────────────
def tokenize(examples, tokenizer):
    return tokenizer(
        examples["text"],
        truncation=True,
        max_length=MAX_LENGTH,
        padding=False,
    )


# ─── Metrics ──────────────────────────────────────────────────────────────────
def compute_metrics(eval_pred):
    logits, labels = eval_pred
    preds = np.argmax(logits, axis=-1)
    # Inline accuracy so we don't need sklearn just for metrics
    accuracy = float(np.mean(preds == labels))
    # Count TP/FP/FN for INJECTION class
    tp = int(np.sum((preds == 1) & (labels == 1)))
    fp = int(np.sum((preds == 1) & (labels == 0)))
    fn = int(np.sum((preds == 0) & (labels == 1)))
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1        = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return {
        "accuracy":  round(accuracy, 4),
        "precision": round(precision, 4),
        "recall":    round(recall, 4),
        "f1":        round(f1, 4),
    }


# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Fine-tune the CASB DeBERTa classifier on custom examples"
    )
    parser.add_argument(
        "--data",
        required=True,
        help="Path to JSONL training file (exported from the ML Trainer tab)"
    )
    parser.add_argument(
        "--epochs",
        type=int,
        default=3,
        help="Number of fine-tuning epochs (default: 3)"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=8,
        help="Training batch size (default: 8, reduce to 4 if OOM)"
    )
    parser.add_argument(
        "--lr",
        type=float,
        default=2e-5,
        help="Learning rate (default: 2e-5)"
    )
    parser.add_argument(
        "--test-split",
        type=float,
        default=0.15,
        help="Fraction of data to use for evaluation (default: 0.15)"
    )
    parser.add_argument(
        "--output",
        default=OUTPUT_DIR,
        help=f"Output directory for the fine-tuned model (default: {OUTPUT_DIR})"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Load and validate data only — do not train"
    )
    args = parser.parse_args()

    print("\n" + "="*60)
    print("  🧠 CASB DeBERTa Fine-Tuning Pipeline")
    print("="*60)

    # ── 1. Load data ──────────────────────────────────────────────────────────
    data_path = Path(args.data)
    if not data_path.exists():
        print(f"\n❌ Data file not found: {data_path}")
        print("   Export samples from the ML Trainer tab at http://localhost:5001")
        sys.exit(1)

    print(f"\n📦 Loading dataset: {data_path}")
    samples = load_jsonl(str(data_path))

    if len(samples) == 0:
        print("❌ No valid samples found in dataset. Check file format.")
        sys.exit(1)

    injection_count = sum(1 for s in samples if s["label"] == 1)
    safe_count      = sum(1 for s in samples if s["label"] == 0)
    print(f"  ✅ {len(samples)} samples loaded")
    print(f"     🚨 INJECTION: {injection_count}  |  ✅ SAFE: {safe_count}")

    if injection_count == 0 or safe_count == 0:
        print("\n⚠️  Warning: Dataset contains only one class. Training may produce a trivial model.")
        print("   Add examples of both INJECTION and SAFE prompts for best results.")

    if args.dry_run:
        print("\n✅ Dry run complete — data is valid. Remove --dry-run to train.")
        return

    if len(samples) < 10:
        print(f"\n⚠️  Only {len(samples)} samples — fine-tuning on very small datasets can overfit.")
        print("   Recommended minimum: 50 samples (25 INJECTION + 25 SAFE).")

    # ── 2. Split ──────────────────────────────────────────────────────────────
    texts  = [s["text"]  for s in samples]
    labels = [s["label"] for s in samples]

    if len(samples) >= 10:
        train_texts, val_texts, train_labels, val_labels = train_test_split(
            texts, labels, test_size=args.test_split, stratify=labels, random_state=42
        )
    else:
        # Too small to split — train on everything
        train_texts, val_texts = texts, texts
        train_labels, val_labels = labels, labels

    print(f"\n📊 Split: {len(train_texts)} train / {len(val_texts)} validation")

    # ── 3. Load tokenizer & model ─────────────────────────────────────────────
    print(f"\n🔄 Loading base model: {BASE_MODEL}")
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForSequenceClassification.from_pretrained(
        BASE_MODEL,
        num_labels=2,
        id2label=ID2LABEL,
        label2id=LABEL2ID,
        ignore_mismatched_sizes=True,
    )
    print(f"  ✅ Model loaded — {sum(p.numel() for p in model.parameters()):,} parameters")

    device = "cuda" if torch.cuda.is_available() else "cpu"
    if device == "cuda":
        print(f"  🚀 GPU detected: {torch.cuda.get_device_name(0)}")
    else:
        print(f"  💻 Running on CPU (this will be slow — expected ~10-30 min for small datasets)")

    # ── 4. Tokenize datasets ──────────────────────────────────────────────────
    train_ds = Dataset.from_dict({"text": train_texts, "labels": train_labels})
    val_ds   = Dataset.from_dict({"text": val_texts,   "labels": val_labels})

    train_ds = train_ds.map(lambda x: tokenize(x, tokenizer), batched=True, remove_columns=["text"])
    val_ds   = val_ds.map(lambda x: tokenize(x, tokenizer), batched=True, remove_columns=["text"])

    collator = DataCollatorWithPadding(tokenizer=tokenizer)

    # ── 5. Training args ──────────────────────────────────────────────────────
    Path(args.output).mkdir(parents=True, exist_ok=True)

    training_args = TrainingArguments(
        output_dir=args.output,
        num_train_epochs=args.epochs,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.batch_size,
        learning_rate=args.lr,
        warmup_ratio=0.1,
        weight_decay=0.01,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
        metric_for_best_model="f1",
        greater_is_better=True,
        logging_steps=10,
        report_to="none",           # Disable wandb/mlflow
        fp16=torch.cuda.is_available(),
        dataloader_pin_memory=False,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        data_collator=collator,
        compute_metrics=compute_metrics,
    )

    # ── 6. Train ──────────────────────────────────────────────────────────────
    print(f"\n🚀 Starting fine-tuning ({args.epochs} epochs, lr={args.lr})...")
    print("   This will take a few minutes. Go grab a coffee ☕\n")
    trainer.train()

    # ── 7. Evaluate ───────────────────────────────────────────────────────────
    print("\n📊 Final evaluation on validation set:")
    results = trainer.evaluate()
    print(f"   Accuracy:  {results.get('eval_accuracy', 0):.1%}")
    print(f"   Precision: {results.get('eval_precision', 0):.1%}")
    print(f"   Recall:    {results.get('eval_recall', 0):.1%}")
    print(f"   F1 Score:  {results.get('eval_f1', 0):.1%}")

    # ── 8. Save model ─────────────────────────────────────────────────────────
    print(f"\n💾 Saving fine-tuned model to: {args.output}")
    trainer.save_model(args.output)
    tokenizer.save_pretrained(args.output)

    print(f"""
{'='*60}
  ✅ Fine-tuning complete!

  Model saved to: {args.output}

  To deploy:
    Restart the CASB gateway — prompt_classifier.py
    will automatically detect and load the fine-tuned
    model from '{args.output}' on next startup.

    ./start_casb.sh

  If performance degrades, delete '{args.output}' and
  restart to revert to the base ProtectAI model.
{'='*60}
""")


if __name__ == "__main__":
    main()
