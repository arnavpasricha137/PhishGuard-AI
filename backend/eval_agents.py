#!/usr/bin/env python3
"""
PhishGuard AI - Agent Evaluation Framework
==========================================

Comprehensive evaluation script for the phishing detection system.
Measures performance of individual agents + consensus model.

Usage:
    python eval_agents.py --dataset labeled_emails.json --output report.json
    python eval_agents.py --dataset labeled_emails.json --output report.html --verbose
"""

import json
import time
import argparse
import requests
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import statistics
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        confusion_matrix, roc_auc_score, roc_curve,
        precision_recall_curve, auc, classification_report
    )
except ImportError:
    print("ERROR: scikit-learn not installed. Run: pip install scikit-learn")
    exit(1)


@dataclass
class AgentScore:
    """Single agent's verdict on an email"""
    score: int  # 0-100
    reason: str
    agent_name: str


@dataclass
class PredictionResult:
    """System prediction for one email"""
    email_id: str
    ground_truth: str
    verdict: str
    score: int
    confidence: float
    agent_scores: Dict[str, AgentScore]
    latency_ms: float
    cache_hit: bool
    error: str = None


@dataclass
class MetricsPerLabel:
    """Metrics for a single class (SAFE, SUSPICIOUS, PHISHING)"""
    label: str
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    
    @property
    def accuracy(self) -> float:
        total = self.tp + self.tn + self.fp + self.fn
        return (self.tp + self.tn) / total if total > 0 else 0.0
    
    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom > 0 else 0.0
    
    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom > 0 else 0.0
    
    @property
    def f1(self) -> float:
        p = self.precision
        r = self.recall
        denom = p + r
        return (2 * p * r) / denom if denom > 0 else 0.0
    
    @property
    def fpr(self) -> float:
        """False Positive Rate"""
        denom = self.fp + self.tn
        return self.fp / denom if denom > 0 else 0.0
    
    @property
    def fnr(self) -> float:
        """False Negative Rate"""
        denom = self.fn + self.tp
        return self.fn / denom if denom > 0 else 0.0


class EvaluationFramework:
    """Main evaluation harness"""
    
    def __init__(self, api_url: str = "http://localhost:8000"):
        self.api_url = api_url
        self.results: List[PredictionResult] = []
        
    def health_check(self) -> bool:
        """Check if backend is running"""
        try:
            resp = requests.get(f"{self.api_url}/health", timeout=5)
            return resp.status_code == 200
        except Exception as e:
            print(f"❌ Backend not reachable: {e}")
            return False
    
    def load_dataset(self, path: str) -> List[Dict]:
        """Load labeled email dataset"""
        with open(path, 'r') as f:
            data = json.load(f)
        emails = data.get("emails", [])
        print(f"✅ Loaded {len(emails)} emails from {path}")
        return emails
    
    def analyze_email(self, email_dict: Dict) -> PredictionResult:
        """Send email to backend and get prediction"""
        email_id = email_dict.get("id", "unknown")
        ground_truth = email_dict.get("ground_truth", "UNKNOWN")
        
        payload = {
            "sender": email_dict["email"].get("sender", ""),
            "subject": email_dict["email"].get("subject", ""),
            "email_text": email_dict["email"].get("email_text", "") or email_dict["email"].get("body", ""),
            "urls": email_dict["email"].get("urls", []),
            "headers": email_dict["email"].get("headers", {})
        }
        
        start = time.time()
        try:
            resp = requests.post(
                f"{self.api_url}/analyze",
                json=payload,
                timeout=30
            )
            latency_ms = (time.time() - start) * 1000
            
            if resp.status_code == 200:
                data = resp.json()
                agent_scores = {
                    agent: AgentScore(
                        score=score_data.get("score", 0),
                        reason=score_data.get("reason", ""),
                        agent_name=agent
                    )
                    for agent, score_data in data.get("agent_scores", {}).items()
                }
                
                return PredictionResult(
                    email_id=email_id,
                    ground_truth=ground_truth,
                    verdict=data.get("verdict", "UNKNOWN"),
                    score=data.get("final_score", data.get("score", 0)),
                    confidence=data.get("confidence", 0.0),
                    agent_scores=agent_scores,
                    latency_ms=latency_ms,
                    cache_hit=data.get("cache_hit", False)
                )
            else:
                return PredictionResult(
                    email_id=email_id,
                    ground_truth=ground_truth,
                    verdict="ERROR",
                    score=0,
                    confidence=0.0,
                    agent_scores={},
                    latency_ms=latency_ms,
                    cache_hit=False,
                    error=f"HTTP {resp.status_code}"
                )
        except Exception as e:
            latency_ms = (time.time() - start) * 1000
            return PredictionResult(
                email_id=email_id,
                ground_truth=ground_truth,
                verdict="ERROR",
                score=0,
                confidence=0.0,
                agent_scores={},
                latency_ms=latency_ms,
                cache_hit=False,
                error=str(e)
            )
    
    def evaluate_dataset(self, emails: List[Dict], verbose: bool = False,
                          workers: int = 10) -> None:
        """Run evaluation on all emails using concurrent requests"""
        print(f"\n🔄 Evaluating {len(emails)} emails with {workers} workers...\n")
        total = len(emails)
        completed = [0]
        results_map = {}

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_idx = {
                executor.submit(self.analyze_email, email): i
                for i, email in enumerate(emails)
            }
            for future in as_completed(future_to_idx):
                i = future_to_idx[future]
                result = future.result()
                results_map[i] = result
                completed[0] += 1

                if verbose or completed[0] % 50 == 0:
                    status = "✅" if result.verdict == result.ground_truth else "❌"
                    print(f"  [{completed[0]}/{total}] {status} {result.email_id}: "
                          f"{result.ground_truth} → {result.verdict} "
                          f"({result.latency_ms:.0f}ms)")

        # Re-order results by original index
        self.results = [results_map[i] for i in range(total)]
        print(f"\n✅ Evaluation complete. {len(self.results)} results collected.")
    
    def compute_consensus_metrics(self) -> Dict:
        """Compute overall consensus model metrics"""
        if not self.results:
            return {}
        
        ground_truth = [r.ground_truth for r in self.results]
        predictions = [r.verdict for r in self.results]
        scores = [r.score for r in self.results]
        
        # Filter out ERROR predictions
        valid_results = [(g, p, s) for g, p, s in zip(ground_truth, predictions, scores) 
                         if p != "ERROR"]
        
        if not valid_results:
            return {"error": "No valid predictions"}
        
        ground_truth_valid, predictions_valid, scores_valid = zip(*valid_results)
        
        # Convert to binary for ROC-AUC (PHISHING=1, else=0)
        y_true_binary = [1 if label == "PHISHING" else 0 for label in ground_truth_valid]
        
        try:
            roc_auc = roc_auc_score(y_true_binary, scores_valid)
        except:
            roc_auc = 0.0
        
        return {
            "total_predictions": len(predictions_valid),
            "accuracy": accuracy_score(ground_truth_valid, predictions_valid),
            "precision_phishing": precision_score(ground_truth_valid, predictions_valid, 
                                                  pos_label="PHISHING", zero_division=0),
            "recall_phishing": recall_score(ground_truth_valid, predictions_valid, 
                                           pos_label="PHISHING", zero_division=0),
            "f1_phishing": f1_score(ground_truth_valid, predictions_valid, 
                                   pos_label="PHISHING", zero_division=0),
            "roc_auc": roc_auc,
            "confusion_matrix": confusion_matrix(ground_truth_valid, predictions_valid,
                                                labels=["SAFE", "SUSPICIOUS", "PHISHING"]).tolist()
        }
    
    def compute_per_agent_metrics(self) -> Dict[str, Dict]:
        """Compute metrics for each individual agent"""
        agents = set()
        for result in self.results:
            agents.update(result.agent_scores.keys())
        
        agent_metrics = {}
        for agent in sorted(agents):
            agent_scores = []
            ground_truth = []
            
            for result in self.results:
                if agent in result.agent_scores:
                    # Convert agent score (0-100) to binary (PHISHING=1 if score > 50)
                    agent_pred = "PHISHING" if result.agent_scores[agent].score > 50 else "SAFE"
                    agent_scores.append(agent_pred)
                    ground_truth.append(result.ground_truth)
            
            if agent_scores:
                agent_metrics[agent] = {
                    "accuracy": accuracy_score(ground_truth, agent_scores),
                    "precision": precision_score(ground_truth, agent_scores, 
                                               pos_label="PHISHING", zero_division=0),
                    "recall": recall_score(ground_truth, agent_scores, 
                                         pos_label="PHISHING", zero_division=0),
                    "f1": f1_score(ground_truth, agent_scores, 
                                 pos_label="PHISHING", zero_division=0),
                }
        
        return agent_metrics
    
    def compute_efficiency_metrics(self) -> Dict:
        """Latency, throughput, cache hit rate"""
        if not self.results:
            return {}
        
        latencies = [r.latency_ms for r in self.results if r.latency_ms > 0]
        cache_hits = sum(1 for r in self.results if r.cache_hit)
        errors = sum(1 for r in self.results if r.error)
        
        latencies.sort()
        
        return {
            "total_requests": len(self.results),
            "successful_requests": len(self.results) - errors,
            "error_rate": errors / len(self.results) if self.results else 0.0,
            "latency_p50_ms": statistics.median(latencies) if latencies else 0,
            "latency_p95_ms": latencies[int(len(latencies) * 0.95)] if latencies else 0,
            "latency_p99_ms": latencies[int(len(latencies) * 0.99)] if latencies else 0,
            "latency_mean_ms": statistics.mean(latencies) if latencies else 0,
            "cache_hit_rate": cache_hits / len(self.results) if self.results else 0.0,
            "throughput_emails_per_min": (len(self.results) / sum(latencies)) * 60000 
                                         if sum(latencies) > 0 else 0,
        }
    
    def identify_failures(self) -> Dict[str, List[Dict]]:
        """Categorize false positives and false negatives"""
        false_positives = []  # Predicted PHISHING, actual SAFE
        false_negatives = []  # Predicted SAFE, actual PHISHING
        
        for result in self.results:
            if result.verdict == "ERROR":
                continue
            
            is_fp = (result.verdict == "PHISHING" and 
                    result.ground_truth in ["SAFE", "SUSPICIOUS"])
            is_fn = (result.verdict in ["SAFE", "SUSPICIOUS"] and 
                    result.ground_truth == "PHISHING")
            
            if is_fp:
                false_positives.append(asdict(result))
            elif is_fn:
                false_negatives.append(asdict(result))
        
        return {
            "false_positives": false_positives[:10],  # Top 10
            "false_negatives": false_negatives[:10],
            "fp_count": len(false_positives),
            "fn_count": len(false_negatives)
        }
    
    def generate_json_report(self, output_path: str) -> None:
        """Write JSON report"""
        consensus_metrics = self.compute_consensus_metrics()
        agent_metrics = self.compute_per_agent_metrics()
        efficiency_metrics = self.compute_efficiency_metrics()
        failures = self.identify_failures()
        
        report = {
            "timestamp": datetime.now().isoformat(),
            "summary": {
                "total_emails_evaluated": len(self.results),
                "consensus_accuracy": consensus_metrics.get("accuracy", 0),
                "phishing_precision": consensus_metrics.get("precision_phishing", 0),
                "phishing_recall": consensus_metrics.get("recall_phishing", 0),
                "phishing_f1": consensus_metrics.get("f1_phishing", 0),
            },
            "consensus_metrics": consensus_metrics,
            "agent_metrics": agent_metrics,
            "efficiency_metrics": efficiency_metrics,
            "failure_analysis": failures,
            "recommendation": self._make_recommendation(consensus_metrics, efficiency_metrics)
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✅ JSON report written to {output_path}")
    
    def generate_html_report(self, output_path: str) -> None:
        """Write HTML report"""
        consensus_metrics = self.compute_consensus_metrics()
        agent_metrics = self.compute_per_agent_metrics()
        efficiency_metrics = self.compute_efficiency_metrics()
        failures = self.identify_failures()
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>PhishGuard AI - Evaluation Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; 
                 margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }}
        h1 {{ color: #333; border-bottom: 3px solid #0066cc; padding-bottom: 10px; }}
        h2 {{ color: #0066cc; margin-top: 30px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: #0066cc; color: white; font-weight: bold; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        .metric {{ display: inline-block; margin: 15px 20px 15px 0; }}
        .metric-value {{ font-size: 24px; font-weight: bold; color: #0066cc; }}
        .metric-label {{ font-size: 12px; color: #666; text-transform: uppercase; }}
        .good {{ color: #22c55e; }}
        .warning {{ color: #f59e0b; }}
        .bad {{ color: #ef4444; }}
        .status-badge {{ padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }}
        .status-pass {{ background: #d4edda; color: #155724; }}
        .status-fail {{ background: #f8d7da; color: #721c24; }}
        .failure-box {{ background: #fef3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 15px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ PhishGuard AI - Agent Evaluation Report</h1>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <h2>Executive Summary</h2>
        <div style="display: flex; flex-wrap: wrap;">
            <div class="metric">
                <div class="metric-label">Accuracy</div>
                <div class="metric-value">{consensus_metrics.get('accuracy', 0):.1%}</div>
            </div>
            <div class="metric">
                <div class="metric-label">Precision (Phishing)</div>
                <div class="metric-value">{consensus_metrics.get('precision_phishing', 0):.1%}</div>
            </div>
            <div class="metric">
                <div class="metric-label">Recall (Phishing)</div>
                <div class="metric-value">{consensus_metrics.get('recall_phishing', 0):.1%}</div>
            </div>
            <div class="metric">
                <div class="metric-label">F1 Score</div>
                <div class="metric-value">{consensus_metrics.get('f1_phishing', 0):.3f}</div>
            </div>
        </div>
        
        <h2>Agent Performance</h2>
        <table>
            <tr>
                <th>Agent</th>
                <th>Accuracy</th>
                <th>Precision</th>
                <th>Recall</th>
                <th>F1 Score</th>
            </tr>
            {self._render_agent_rows(agent_metrics)}
        </table>
        
        <h2>Efficiency Metrics</h2>
        <table>
            <tr>
                <th>Metric</th>
                <th>Value</th>
            </tr>
            <tr>
                <td>P50 Latency</td>
                <td>{efficiency_metrics.get('latency_p50_ms', 0):.0f}ms</td>
            </tr>
            <tr>
                <td>P95 Latency</td>
                <td>{efficiency_metrics.get('latency_p95_ms', 0):.0f}ms</td>
            </tr>
            <tr>
                <td>Cache Hit Rate</td>
                <td>{efficiency_metrics.get('cache_hit_rate', 0):.1%}</td>
            </tr>
            <tr>
                <td>Error Rate</td>
                <td>{efficiency_metrics.get('error_rate', 0):.1%}</td>
            </tr>
        </table>
        
        <h2>Failure Analysis</h2>
        <p><strong>False Positives:</strong> {failures.get('fp_count', 0)} 
           | <strong>False Negatives:</strong> {failures.get('fn_count', 0)}</p>
    </div>
</body>
</html>
"""
        
        with open(output_path, 'w') as f:
            f.write(html)
        
        print(f"✅ HTML report written to {output_path}")
    
    def _render_agent_rows(self, agent_metrics: Dict) -> str:
        rows = []
        for agent, metrics in agent_metrics.items():
            rows.append(f"""
            <tr>
                <td>{agent}</td>
                <td>{metrics.get('accuracy', 0):.1%}</td>
                <td>{metrics.get('precision', 0):.1%}</td>
                <td>{metrics.get('recall', 0):.1%}</td>
                <td>{metrics.get('f1', 0):.3f}</td>
            </tr>
            """)
        return "".join(rows)
    
    def _make_recommendation(self, consensus: Dict, efficiency: Dict) -> str:
        """Determine if system is production-ready"""
        issues = []
        
        if consensus.get("accuracy", 0) < 0.92:
            issues.append(f"Accuracy too low: {consensus.get('accuracy', 0):.1%} (target ≥ 92%)")
        
        if consensus.get("precision_phishing", 0) < 0.95:
            issues.append(f"Precision too low: {consensus.get('precision_phishing', 0):.1%} (target ≥ 95%)")
        
        if consensus.get("recall_phishing", 0) < 0.90:
            issues.append(f"Recall too low: {consensus.get('recall_phishing', 0):.1%} (target ≥ 90%)")
        
        if efficiency.get("latency_p95_ms", float('inf')) > 2000:
            issues.append(f"P95 latency too high: {efficiency.get('latency_p95_ms', 0):.0f}ms (target < 2000ms)")
        
        if efficiency.get("error_rate", 0) > 0.01:
            issues.append(f"Error rate too high: {efficiency.get('error_rate', 0):.1%} (target < 1%)")
        
        if not issues:
            return "✅ PRODUCTION-READY: All metrics pass thresholds."
        else:
            return "⚠️ REVIEW NEEDED:\n  • " + "\n  • ".join(issues)


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate PhishGuard AI agent system"
    )
    parser.add_argument("--dataset", required=True, help="Path to labeled_emails.json")
    parser.add_argument("--output", default="evaluation_report.json", help="Output file path")
    parser.add_argument("--api", default="http://localhost:8000", help="Backend API URL")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--html", action="store_true", help="Also generate HTML report")
    parser.add_argument("--workers", type=int, default=5,
                        help="Concurrent workers for evaluation (default: 5)")
    
    args = parser.parse_args()
    
    framework = EvaluationFramework(api_url=args.api)
    
    print("🛡️  PhishGuard AI - Agent Evaluation Framework\n")
    
    # Health check
    if not framework.health_check():
        exit(1)
    
    # Load dataset
    emails = framework.load_dataset(args.dataset)
    if not emails:
        print("❌ No emails found in dataset")
        exit(1)
    
    # Run evaluation
    framework.evaluate_dataset(emails, verbose=args.verbose, workers=args.workers)
    
    # Generate reports
    framework.generate_json_report(args.output)
    if args.html:
        html_output = args.output.replace(".json", ".html")
        framework.generate_html_report(html_output)
    
    # Print summary
    consensus = framework.compute_consensus_metrics()
    print(f"\n📊 RESULTS:")
    print(f"   Accuracy:        {consensus.get('accuracy', 0):.1%}")
    print(f"   Precision (φ):   {consensus.get('precision_phishing', 0):.1%}")
    print(f"   Recall (φ):      {consensus.get('recall_phishing', 0):.1%}")
    print(f"   F1 Score:        {consensus.get('f1_phishing', 0):.3f}")
    print(f"\n✅ Done! Review {args.output}")


if __name__ == "__main__":
    main()
