"""
Consensus Agent.
Combines outputs from all specialist agents into final verdict.
"""

from typing import Dict, List, Any


class ConsensusAgent:
    """Combines agent outputs into final verdict with weighted scoring."""
    
    # Verdict thresholds
    SAFE_THRESHOLD = 39
    SUSPICIOUS_THRESHOLD = 69
    
    # Agent weights
    WEIGHTS = {
        "url_agent": 0.35,
        "content_agent": 0.30,
        "header_agent": 0.20,
        "reputation_agent": 0.15
    }
    
    def __init__(self):
        """Initialize consensus agent."""
        pass
    
    def combine_results(
        self,
        url_result: Dict[str, Any],
        content_result: Dict[str, Any],
        header_result: Dict[str, Any],
        reputation_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Combine all agent results into final verdict.
        
        Args:
            url_result: URL agent output
            content_result: Content agent output
            header_result: Header agent output
            reputation_result: Reputation agent output
            
        Returns:
            Final verdict with score, label, and combined signals
        """
        # Extract scores
        url_score = url_result.get("score", 0)
        content_score = content_result.get("score", 0)
        header_score = header_result.get("score", 0)
        reputation_score = reputation_result.get("score", 0)
        
        # Calculate weighted average
        weighted_score = (
            self.WEIGHTS["url_agent"] * url_score +
            self.WEIGHTS["content_agent"] * content_score +
            self.WEIGHTS["header_agent"] * header_score +
            self.WEIGHTS["reputation_agent"] * reputation_score
        )
        
        # Get max signal (strongest indicator)
        max_score = max(url_score, content_score, header_score, reputation_score)
        
        # Combine weighted and max (60% weighted, 40% max)
        final_score = int((weighted_score * 0.6) + (max_score * 0.4))
        
        # Apply critical overrides
        spear_phishing = content_result.get("spear_phishing_detected", False)
        
        if url_score >= 70:
            final_score = max(final_score, 72)
        
        if content_score >= 80:
            final_score = max(final_score, 75)
        
        if header_score >= 70:
            final_score = max(final_score, 68)
        
        if spear_phishing:
            final_score = max(final_score, 80)
        
        # Check for brand spoofing in URL signals
        url_signals = url_result.get("signals", [])
        has_brand_spoofing = any(
            "brand spoofing" in signal.lower() or "impersonation" in signal.lower()
            for signal in url_signals
        )
        
        if has_brand_spoofing:
            final_score = max(final_score, 78)
        
        # Normalize
        final_score = min(final_score, 100)
        
        # Determine verdict label
        if final_score >= self.SUSPICIOUS_THRESHOLD + 1:
            verdict = "PHISHING"
        elif final_score >= self.SAFE_THRESHOLD + 1:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"
        
        # Calculate confidence (same as score for now)
        confidence = final_score / 100.0
        
        # Combine all signals
        all_signals = []
        
        # Add agent-specific signals with prefixes
        for signal in url_result.get("signals", []):
            if signal and "No" not in signal and "appear" not in signal:
                all_signals.append(f"[URL] {signal}")
        
        for signal in content_result.get("signals", []):
            if signal and "No" not in signal and "appear" not in signal:
                all_signals.append(f"[Content] {signal}")
        
        for signal in header_result.get("signals", []):
            if signal and "No" not in signal and "appear" not in signal:
                all_signals.append(f"[Header] {signal}")
        
        for signal in reputation_result.get("signals", []):
            if signal and "No" not in signal and "appear" not in signal:
                all_signals.append(f"[Reputation] {signal}")
        
        # If no signals, add default
        if not all_signals:
            all_signals = ["No significant phishing indicators detected"]
        
        # Limit to top 20 signals
        all_signals = all_signals[:20]
        
        return {
            "verdict": verdict,
            "confidence": confidence,
            "final_score": final_score,
            "agent_scores": {
                "url_agent": {
                    "score": url_score,
                    "signals": url_result.get("signals", [])[:5]
                },
                "content_agent": {
                    "score": content_score,
                    "signals": content_result.get("signals", [])[:5]
                },
                "header_agent": {
                    "score": header_score,
                    "signals": header_result.get("signals", [])[:5]
                },
                "reputation_agent": {
                    "score": reputation_score,
                    "signals": reputation_result.get("signals", [])[:5]
                }
            },
            "all_reasons": all_signals,
            "spear_phishing_detected": spear_phishing,
            "url_verdicts": url_result.get("url_verdicts", []),
            "highlighted_phrases": content_result.get("highlighted_phrases", [])
        }


def get_consensus_agent() -> ConsensusAgent:
    """
    Get consensus agent instance.
    
    Returns:
        ConsensusAgent instance
    """
    return ConsensusAgent()
