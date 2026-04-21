#!/usr/bin/env python3
"""
Convert raw CSV email datasets into labeled_emails.json for eval_agents.py.

Supported datasets (auto-detected):
  - CEAS_08.csv, SpamAssasin.csv, Nazario.csv  (sender/body/label/urls)
  - Enron.csv, Ling.csv                        (subject/body/label)
  - phishing_email.csv                          (text_combined/label)
  - Nigerian_Fraud.csv                          (all phishing)

Usage:
    python prepare_dataset.py --input /path/to/dataset/dir --output eval/labeled_emails.json
    python prepare_dataset.py --input /path/to/dataset/dir --output eval/labeled_emails.json --per-file 100 --seed 42
"""

import csv
import json
import os
import sys
import random
import argparse
import re
from pathlib import Path

csv.field_size_limit(10 * 1024 * 1024)  # 10 MB limit for large email bodies

URL_RE = re.compile(r'https?://\S+|www\.\S+', re.IGNORECASE)


def label_to_verdict(raw_label: str, filename: str) -> str:
    """Map CSV label value to SAFE / PHISHING."""
    val = str(raw_label).strip().lower()
    # 1 = phishing/spam in all included datasets
    if val in ("1", "phishing", "spam", "phish"):
        return "PHISHING"
    if val in ("0", "ham", "safe", "legit", "legitimate"):
        return "SAFE"
    return None  # skip unknown labels


def extract_urls(raw_urls: str) -> list:
    """Parse a URLs field which may be CSV-separated strings or a Python list repr."""
    if not raw_urls or raw_urls.strip() in ("", "[]", "nan"):
        return []
    # Try JSON / Python list format
    try:
        parsed = json.loads(raw_urls.replace("'", '"'))
        if isinstance(parsed, list):
            return [u for u in parsed if u]
    except Exception:
        pass
    # Fallback: extract via regex
    return URL_RE.findall(raw_urls)


def read_csv_safe(path: str):
    """Yield rows from a CSV with a large field-size limit, skipping bad rows."""
    with open(path, encoding="utf-8", errors="ignore") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            try:
                yield row
            except csv.Error:
                continue


def load_dataset(csv_path: Path, per_file_limit: int, rng: random.Random) -> list:
    """Load and sample emails from a single CSV file."""
    filename = csv_path.name
    rows_phishing = []
    rows_safe = []

    for row in read_csv_safe(str(csv_path)):
        cols = {k.lower().strip() for k in row.keys()}

        # Determine label column
        label_raw = None
        for col in ("label", "class", "type"):
            if col in {k.lower() for k in row}:
                # find the actual key with original casing
                actual = next(k for k in row if k.lower() == col)
                label_raw = row[actual]
                break

        if label_raw is None:
            continue

        verdict = label_to_verdict(label_raw, filename)
        if verdict is None:
            continue

        # Build normalised email dict
        email = {}
        row_lower = {k.lower().strip(): v for k, v in row.items()}

        email["sender"] = row_lower.get("sender", "")
        email["subject"] = row_lower.get("subject", "")[:300]

        # Body field
        body = (row_lower.get("body") or
                row_lower.get("text_combined") or
                row_lower.get("text") or "")
        email["email_text"] = body[:2000]  # cap for API payload size; matches AnalyzeRequest field name

        # URLs
        raw_urls = row_lower.get("urls", "") or row_lower.get("url", "") or ""
        email["urls"] = extract_urls(raw_urls)[:10]

        email["headers"] = {}

        if verdict == "PHISHING":
            rows_phishing.append(email)
        else:
            rows_safe.append(email)

        # Early exit once we have enough
        if len(rows_phishing) >= per_file_limit * 4 and len(rows_safe) >= per_file_limit * 4:
            break

    # Sample equally from each class (up to per_file_limit each)
    sampled_phishing = rng.sample(rows_phishing, min(per_file_limit, len(rows_phishing)))
    sampled_safe = rng.sample(rows_safe, min(per_file_limit, len(rows_safe)))

    print(f"  {filename}: {len(rows_phishing)} phishing, {len(rows_safe)} safe "
          f"→ sampled {len(sampled_phishing)} + {len(sampled_safe)}")

    return (
        [{"verdict": "PHISHING", "email": e} for e in sampled_phishing] +
        [{"verdict": "SAFE", "email": e} for e in sampled_safe]
    )


def build_labeled_json(input_dir: str, output_path: str,
                        per_file: int = 100, seed: int = 42) -> None:
    rng = random.Random(seed)
    input_dir = Path(input_dir)

    csv_files = sorted(input_dir.glob("*.csv"))
    if not csv_files:
        print(f"❌ No CSV files found in {input_dir}")
        sys.exit(1)

    print(f"📂 Found {len(csv_files)} CSV files in {input_dir}\n")

    all_entries = []
    for csv_path in csv_files:
        size_mb = csv_path.stat().st_size / 1_048_576
        print(f"→ Loading {csv_path.name}  ({size_mb:.1f} MB)")
        entries = load_dataset(csv_path, per_file, rng)
        all_entries.extend(entries)

    # Shuffle and assign IDs
    rng.shuffle(all_entries)
    emails_out = []
    for i, entry in enumerate(all_entries):
        emails_out.append({
            "id": f"email_{i+1:04d}",
            "ground_truth": entry["verdict"],
            "email": entry["email"]
        })

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as fh:
        json.dump({"emails": emails_out}, fh, indent=2)

    # Summary
    phishing_count = sum(1 for e in emails_out if e["ground_truth"] == "PHISHING")
    safe_count = sum(1 for e in emails_out if e["ground_truth"] == "SAFE")
    print(f"\n{'='*55}")
    print(f"✅ Dataset written to: {output_path}")
    print(f"   Total emails : {len(emails_out)}")
    print(f"   PHISHING     : {phishing_count}")
    print(f"   SAFE         : {safe_count}")
    print(f"{'='*55}")
    print(f"\nNext step:")
    print(f"  python eval_agents.py --dataset {output_path} --output eval/baseline_report.json --html --verbose")


def main():
    parser = argparse.ArgumentParser(description="Convert CSV email datasets to labeled_emails.json")
    parser.add_argument("--input", required=True,
                        help="Directory containing CSV dataset files")
    parser.add_argument("--output", default="eval/labeled_emails.json",
                        help="Output JSON path (default: eval/labeled_emails.json)")
    parser.add_argument("--per-file", type=int, default=100,
                        help="Max emails to sample per class per CSV file (default: 100)")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed for reproducibility (default: 42)")
    args = parser.parse_args()

    build_labeled_json(args.input, args.output, args.per_file, args.seed)


if __name__ == "__main__":
    main()
