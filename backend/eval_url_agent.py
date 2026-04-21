#!/usr/bin/env python3
"""
PhishGuard URL Detection Evaluator
===================================
Measures how accurately the URL Agent + Reputation Agent detect phishing URLs
in isolation — separate from email body / header signals.

Dataset: PhiUSIIL_Phishing_URL_Dataset.csv
  label=0  →  PHISHING
  label=1  →  LEGITIMATE

Usage:
    python eval_url_agent.py \\
        --dataset /path/to/PhiUSIIL_Phishing_URL_Dataset.csv \\
        --sample 400 \\
        --workers 5 \\
        --output eval/url_eval_report.json \\
        --html
"""

import csv
import json
import random
import time
import argparse
from pathlib import Path
from dataclasses import dataclass, asdict
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict

import requests

try:
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score,
        f1_score, confusion_matrix, roc_auc_score
    )
    SKLEARN = True
except ImportError:
    print("WARNING: scikit-learn not installed — some metrics skipped.")
    SKLEARN = False

csv.field_size_limit(10 * 1024 * 1024)


# ─── Data model ──────────────────────────────────────────────────────────────

@dataclass
class URLResult:
    url: str
    ground_truth: str          # "PHISHING" | "SAFE"
    verdict: str               # "PHISHING" | "SUSPICIOUS" | "SAFE" | "ERROR"
    final_score: int
    url_agent_score: int
    reputation_agent_score: int
    latency_ms: float
    error: str = ""


# ─── Dataset loader ───────────────────────────────────────────────────────────

def load_urls(csv_path: str, sample: int, seed: int = 42) -> List[Dict]:
    """Sample balanced phishing/safe URLs from the CSV."""
    rng = random.Random(seed)
    phishing_urls, safe_urls = [], []

    with open(csv_path, encoding="utf-8", errors="ignore") as fh:
        reader = csv.DictReader(fh)
        # Strip BOM from first column name
        reader.fieldnames = [f.lstrip("\ufeff") for f in reader.fieldnames]
        for row in reader:
            url = row.get("URL", "").strip()
            label = row.get("label", "").strip()
            if not url or label not in ("0", "1"):
                continue
            if label == "0":
                phishing_urls.append(url)
            else:
                safe_urls.append(url)

    per_class = sample // 2
    sampled_phishing = rng.sample(phishing_urls, min(per_class, len(phishing_urls)))
    sampled_safe = rng.sample(safe_urls, min(per_class, len(safe_urls)))

    entries = (
        [{"url": u, "ground_truth": "PHISHING"} for u in sampled_phishing] +
        [{"url": u, "ground_truth": "SAFE"} for u in sampled_safe]
    )
    rng.shuffle(entries)
    print(f"  Sampled {len(sampled_phishing)} phishing + {len(sampled_safe)} safe = {len(entries)} URLs")
    return entries


# ─── Analyser ─────────────────────────────────────────────────────────────────

def analyze_url(entry: Dict, api_url: str, timeout: int) -> URLResult:
    """Send a minimal email containing only this URL to the backend."""
    url = entry["url"]
    ground_truth = entry["ground_truth"]

    # Neutral payload — empty body, PASS headers so ONLY url_agent
    # and reputation_agent drive the score. This isolates URL detection.
    payload = {
        "email_text": "",
        "subject": "",
        "sender": "",
        "urls": [url],
        "headers": {
            "spf": "PASS",
            "dkim": "PASS",
            "dmarc": "PASS"
        }
    }

    start = time.time()
    try:
        resp = requests.post(
            f"{api_url}/analyze",
            json=payload,
            timeout=timeout
        )
        latency_ms = (time.time() - start) * 1000

        if resp.status_code == 200:
            data = resp.json()
            agent_scores = data.get("agent_scores", {})
            return URLResult(
                url=url,
                ground_truth=ground_truth,
                verdict=data.get("verdict", "UNKNOWN"),
                final_score=data.get("final_score", data.get("score", 0)),
                url_agent_score=agent_scores.get("url_agent", {}).get("score", 0),
                reputation_agent_score=agent_scores.get("reputation_agent", {}).get("score", 0),
                latency_ms=latency_ms
            )
        else:
            return URLResult(url=url, ground_truth=ground_truth, verdict="ERROR",
                             final_score=0, url_agent_score=0, reputation_agent_score=0,
                             latency_ms=(time.time() - start) * 1000,
                             error=f"HTTP {resp.status_code}")
    except Exception as exc:
        return URLResult(url=url, ground_truth=ground_truth, verdict="ERROR",
                         final_score=0, url_agent_score=0, reputation_agent_score=0,
                         latency_ms=(time.time() - start) * 1000,
                         error=str(exc))


# ─── Runner ───────────────────────────────────────────────────────────────────

def run_eval(entries: List[Dict], api_url: str, workers: int,
             timeout: int) -> List[URLResult]:
    total = len(entries)
    results_map: Dict[int, URLResult] = {}
    completed = [0]

    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_idx = {
            executor.submit(analyze_url, e, api_url, timeout): i
            for i, e in enumerate(entries)
        }
        for future in as_completed(future_to_idx):
            i = future_to_idx[future]
            result = future.result()
            results_map[i] = result
            completed[0] += 1
            if completed[0] % 50 == 0:
                correct = sum(
                    1 for r in results_map.values()
                    if r.verdict != "ERROR" and (
                        (r.verdict == "PHISHING" and r.ground_truth == "PHISHING") or
                        (r.verdict in ("SAFE", "SUSPICIOUS") and r.ground_truth == "SAFE")
                    )
                )
                non_error = sum(1 for r in results_map.values() if r.verdict != "ERROR")
                pct = (correct / non_error * 100) if non_error else 0
                print(f"  [{completed[0]}/{total}] running accuracy: {pct:.1f}%")

    return [results_map[i] for i in range(total)]


# ─── Metrics ──────────────────────────────────────────────────────────────────

def compute_metrics(results: List[URLResult]) -> Dict:
    valid = [r for r in results if r.verdict != "ERROR"]
    errors = len(results) - len(valid)

    if not valid:
        return {"error": "No valid results"}

    # Binary labels: PHISHING=1, else=0
    y_true = [1 if r.ground_truth == "PHISHING" else 0 for r in valid]
    # SUSPICIOUS is treated as predicted phishing (conservative)
    y_pred = [1 if r.verdict in ("PHISHING", "SUSPICIOUS") else 0 for r in valid]
    y_score = [r.final_score / 100.0 for r in valid]

    metrics = {
        "total_urls": len(results),
        "valid_urls": len(valid),
        "error_count": errors,
        "phishing_count": sum(1 for r in valid if r.ground_truth == "PHISHING"),
        "safe_count": sum(1 for r in valid if r.ground_truth == "SAFE"),
    }

    if SKLEARN:
        metrics.update({
            "accuracy": round(accuracy_score(y_true, y_pred) * 100, 2),
            "precision": round(precision_score(y_true, y_pred, zero_division=0) * 100, 2),
            "recall": round(recall_score(y_true, y_pred, zero_division=0) * 100, 2),
            "f1_score": round(f1_score(y_true, y_pred, zero_division=0), 4),
            "roc_auc": round(roc_auc_score(y_true, y_score), 4) if len(set(y_true)) > 1 else None,
        })
        tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
        metrics.update({
            "true_positives": int(tp),   # correctly caught phishing
            "false_negatives": int(fn),  # missed phishing (dangerous)
            "true_negatives": int(tn),   # correctly flagged safe
            "false_positives": int(fp),  # safe links flagged as phishing (annoying)
        })

    latencies = [r.latency_ms for r in valid]
    metrics["latency_p50_ms"] = round(sorted(latencies)[len(latencies) // 2], 1)
    metrics["latency_p95_ms"] = round(sorted(latencies)[int(len(latencies) * 0.95)], 1)
    metrics["latency_mean_ms"] = round(sum(latencies) / len(latencies), 1)

    # Per-verdict breakdown
    from collections import Counter
    verdict_counts = Counter(r.verdict for r in valid)
    metrics["verdict_distribution"] = dict(verdict_counts)

    # Missed phishing (false negatives) — most important failures
    missed = [r for r in valid if r.ground_truth == "PHISHING" and r.verdict == "SAFE"]
    metrics["missed_phishing_sample"] = [
        {"url": r.url, "url_score": r.url_agent_score, "rep_score": r.reputation_agent_score}
        for r in missed[:10]
    ]

    # False alarms (false positives)
    false_alarms = [r for r in valid
                    if r.ground_truth == "SAFE" and r.verdict in ("PHISHING", "SUSPICIOUS")]
    metrics["false_alarm_sample"] = [
        {"url": r.url, "url_score": r.url_agent_score}
        for r in false_alarms[:10]
    ]

    return metrics


# ─── HTML report ──────────────────────────────────────────────────────────────

def generate_html(metrics: Dict, output_path: str) -> None:
    acc = metrics.get("accuracy", "N/A")
    prec = metrics.get("precision", "N/A")
    rec = metrics.get("recall", "N/A")
    f1 = metrics.get("f1_score", "N/A")
    auc = metrics.get("roc_auc", "N/A")

    def badge(val, green_thresh, yellow_thresh):
        if val == "N/A":
            return "#888"
        return "#22c55e" if val >= green_thresh else "#f59e0b" if val >= yellow_thresh else "#ef4444"

    missed_rows = "".join(
        f"<tr><td style='word-break:break-all;max-width:400px'>{m['url']}</td>"
        f"<td>{m['url_score']}</td><td>{m['rep_score']}</td></tr>"
        for m in metrics.get("missed_phishing_sample", [])
    )
    alarm_rows = "".join(
        f"<tr><td style='word-break:break-all;max-width:400px'>{a['url']}</td>"
        f"<td>{a['url_score']}</td></tr>"
        for a in metrics.get("false_alarm_sample", [])
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>PhishGuard URL Detection Report</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 0; background: #0f172a; color: #e2e8f0; }}
  .wrap {{ max-width: 960px; margin: 0 auto; padding: 2rem; }}
  h1 {{ color: #38bdf8; }} h2 {{ color: #94a3b8; border-bottom: 1px solid #334155; padding-bottom:.5rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin: 1.5rem 0; }}
  .card {{ background: #1e293b; border-radius: 8px; padding: 1.2rem; text-align: center; }}
  .card .val {{ font-size: 2rem; font-weight: 700; }}
  .card .lbl {{ font-size: .8rem; color: #64748b; margin-top:.3rem; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
  th {{ background: #1e293b; padding: .5rem .75rem; text-align:left; }}
  td {{ padding: .4rem .75rem; border-bottom: 1px solid #1e293b; }}
  tr:hover td {{ background: #1e293b44; }}
  .tag {{ display:inline-block; padding:.2rem .6rem; border-radius:9999px; font-size:.75rem; font-weight:600; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>🛡️ PhishGuard — URL Detection Evaluation</h1>
  <p style="color:#64748b">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} &nbsp;|&nbsp;
     Dataset: PhiUSIIL &nbsp;|&nbsp; {metrics.get('valid_urls','?')} URLs evaluated</p>

  <h2>Performance Summary</h2>
  <div class="grid">
    <div class="card">
      <div class="val" style="color:{badge(acc,90,75)}">{acc}%</div>
      <div class="lbl">Accuracy</div>
    </div>
    <div class="card">
      <div class="val" style="color:{badge(prec,95,80)}">{prec}%</div>
      <div class="lbl">Precision</div>
    </div>
    <div class="card">
      <div class="val" style="color:{badge(rec,90,70)}">{rec}%</div>
      <div class="lbl">Recall</div>
    </div>
    <div class="card">
      <div class="val" style="color:{badge(f1*100 if isinstance(f1,float) else 0,0.90,0.75)}">{f1}</div>
      <div class="lbl">F1 Score</div>
    </div>
    <div class="card">
      <div class="val" style="color:#38bdf8">{auc}</div>
      <div class="lbl">ROC-AUC</div>
    </div>
  </div>

  <h2>Confusion Matrix</h2>
  <div class="grid" style="grid-template-columns:repeat(2,1fr);max-width:400px">
    <div class="card">
      <div class="val" style="color:#22c55e">{metrics.get('true_positives','?')}</div>
      <div class="lbl">True Positives<br>(caught phishing)</div>
    </div>
    <div class="card">
      <div class="val" style="color:#ef4444">{metrics.get('false_negatives','?')}</div>
      <div class="lbl">False Negatives<br>(missed phishing ⚠️)</div>
    </div>
    <div class="card">
      <div class="val" style="color:#f59e0b">{metrics.get('false_positives','?')}</div>
      <div class="lbl">False Positives<br>(false alarms)</div>
    </div>
    <div class="card">
      <div class="val" style="color:#22c55e">{metrics.get('true_negatives','?')}</div>
      <div class="lbl">True Negatives<br>(correct safe)</div>
    </div>
  </div>

  <h2>Latency</h2>
  <div class="grid" style="grid-template-columns:repeat(3,1fr);max-width:480px">
    <div class="card"><div class="val">{metrics.get('latency_p50_ms','?')}ms</div><div class="lbl">p50</div></div>
    <div class="card"><div class="val">{metrics.get('latency_p95_ms','?')}ms</div><div class="lbl">p95</div></div>
    <div class="card"><div class="val">{metrics.get('latency_mean_ms','?')}ms</div><div class="lbl">mean</div></div>
  </div>

  <h2>Missed Phishing URLs (False Negatives)</h2>
  <table>
    <tr><th>URL</th><th>URL Score</th><th>Rep Score</th></tr>
    {missed_rows if missed_rows else '<tr><td colspan="3" style="color:#22c55e">None! All phishing URLs caught.</td></tr>'}
  </table>

  <h2>False Alarm URLs (Safe → Flagged)</h2>
  <table>
    <tr><th>URL</th><th>URL Score</th></tr>
    {alarm_rows if alarm_rows else '<tr><td colspan="2" style="color:#22c55e">None!</td></tr>'}
  </table>
</div>
</body>
</html>"""

    Path(output_path).write_text(html)
    print(f"✅ HTML report → {output_path}")


# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="PhishGuard URL Detection Evaluator")
    parser.add_argument("--dataset", required=True,
                        help="Path to PhiUSIIL_Phishing_URL_Dataset.csv")
    parser.add_argument("--sample", type=int, default=400,
                        help="Total URLs to evaluate — split 50/50 (default: 400)")
    parser.add_argument("--workers", type=int, default=5,
                        help="Concurrent request workers (default: 5)")
    parser.add_argument("--timeout", type=int, default=30,
                        help="Per-request timeout seconds (default: 30)")
    parser.add_argument("--api", default="http://localhost:8000",
                        help="Backend API URL")
    parser.add_argument("--output", default="eval/url_eval_report.json",
                        help="Output JSON path")
    parser.add_argument("--html", action="store_true",
                        help="Also write HTML report")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed for reproducibility")
    args = parser.parse_args()

    print("🔗 PhishGuard — URL Detection Evaluator\n")

    # Health check
    try:
        resp = requests.get(f"{args.api}/health", timeout=5)
        data = resp.json()
        print(f"✅ Backend: {data.get('status')} | Redis: {data.get('redis')}")
    except Exception as e:
        print(f"❌ Backend not reachable: {e}")
        return

    # Load dataset
    print(f"\n📂 Loading dataset: {args.dataset}")
    entries = load_urls(args.dataset, args.sample, args.seed)

    # Run evaluation
    print(f"\n🔄 Evaluating {len(entries)} URLs with {args.workers} workers...\n")
    t0 = time.time()
    results = run_eval(entries, args.api, args.workers, args.timeout)
    elapsed = time.time() - t0
    print(f"\n✅ Done in {elapsed:.1f}s\n")

    # Metrics
    metrics = compute_metrics(results)
    metrics["evaluated_at"] = datetime.now().isoformat()
    metrics["elapsed_seconds"] = round(elapsed, 1)

    # Print summary
    print("📊 URL DETECTION RESULTS:")
    print(f"   Accuracy:    {metrics.get('accuracy', 'N/A')}%")
    print(f"   Precision:   {metrics.get('precision', 'N/A')}%  (of URLs flagged phishing, how many were?)")
    print(f"   Recall:      {metrics.get('recall', 'N/A')}%  (of actual phishing URLs, how many caught?)")
    print(f"   F1 Score:    {metrics.get('f1_score', 'N/A')}")
    print(f"   ROC-AUC:     {metrics.get('roc_auc', 'N/A')}")
    print(f"   Latency p95: {metrics.get('latency_p95_ms', 'N/A')}ms")
    print(f"   Errors:      {metrics.get('error_count', 0)}/{metrics.get('total_urls', 0)}")
    print(f"\n   Confusion Matrix:")
    print(f"     Caught phishing (TP): {metrics.get('true_positives', '?')}")
    print(f"     Missed phishing (FN): {metrics.get('false_negatives', '?')}  ← dangerous")
    print(f"     False alarms    (FP): {metrics.get('false_positives', '?')}  ← annoying")
    print(f"     Correct safe    (TN): {metrics.get('true_negatives', '?')}")

    # Write reports
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(metrics, indent=2))
    print(f"\n✅ JSON report → {args.output}")

    if args.html:
        generate_html(metrics, args.output.replace(".json", ".html"))


if __name__ == "__main__":
    main()
