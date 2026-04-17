"""
URL Analysis Agent.
Analyzes URLs for phishing indicators using lexical features and brand detection.
"""

import asyncio
from typing import Dict, List, Any
from ml.url_features import get_url_feature_extractor
from ml.brand_detector import get_brand_detector
from cache.redis_client import redis_client


class URLAgent:
    """Specialist agent for URL analysis."""
    
    def __init__(self):
        """Initialize URL agent with feature extractor and brand detector."""
        self.feature_extractor = get_url_feature_extractor()
        self.brand_detector = get_brand_detector()
    
    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """
        Analyze a single URL for phishing indicators.
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary with score, verdict, and signals
        """
        # Check cache first
        cached = await redis_client.get_verdict(url)
        if cached:
            return cached
        
        # Extract features
        features = self.feature_extractor.extract_all_features(url)
        
        # Calculate base risk score
        base_score, base_reasons = self.feature_extractor.calculate_risk_score(features)
        
        # Check for brand spoofing
        is_spoofing, spoof_reasons = self.brand_detector.detect_url_spoofing(
            url, 
            features["full_domain"]
        )
        
        # Combine scores
        score = base_score
        reasons = base_reasons.copy()
        
        if is_spoofing:
            score = min(score + 25, 100)
            reasons.extend(spoof_reasons)
        
        # Determine verdict
        if score >= 70:
            verdict = "PHISHING"
        elif score >= 40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"
        
        result = {
            "url": url,
            "score": score,
            "verdict": verdict,
            "signals": reasons,
            "features": {
                "domain": features["full_domain"],
                "tld": features["tld"],
                "is_https": features["is_https"],
                "is_shortener": features["is_shortener"],
                "has_ip": features["has_ip_address"]
            }
        }
        
        # Cache the result
        await redis_client.set_verdict(url, result)
        
        return result
    
    async def analyze(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze all URLs in the email payload.
        
        Args:
            payload: Email payload with URLs list
            
        Returns:
            Agent result with score and signals
        """
        urls = payload.get("urls", [])
        
        if not urls:
            return {
                "score": 0,
                "signals": ["No URLs found in email"],
                "url_verdicts": []
            }
        
        # Analyze all URLs in parallel
        tasks = [self.analyze_url(url) for url in urls]
        url_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle exceptions
        url_verdicts = []
        for i, result in enumerate(url_results):
            if isinstance(result, Exception):
                url_verdicts.append({
                    "url": urls[i],
                    "score": 0,
                    "verdict": "ERROR",
                    "signals": [f"Analysis error: {str(result)}"]
                })
            else:
                url_verdicts.append(result)
        
        # Calculate aggregate score
        if url_verdicts:
            # Use max score (worst URL)
            max_score = max(v["score"] for v in url_verdicts)
            avg_score = sum(v["score"] for v in url_verdicts) / len(url_verdicts)
            
            # Weighted: 70% max, 30% average
            final_score = int(max_score * 0.7 + avg_score * 0.3)
        else:
            final_score = 0
        
        # Collect all signals
        all_signals = []
        for verdict in url_verdicts:
            if verdict["score"] >= 40:  # Only include suspicious/phishing URLs
                all_signals.extend([
                    f"[{verdict['url'][:50]}...] {signal}"
                    for signal in verdict["signals"]
                ])
        
        if not all_signals:
            all_signals = ["All URLs appear safe"]
        
        return {
            "score": final_score,
            "signals": all_signals[:10],  # Limit to top 10 signals
            "url_verdicts": url_verdicts
        }


def get_url_agent() -> URLAgent:
    """
    Get URL agent instance.
    
    Returns:
        URLAgent instance
    """
    return URLAgent()
