"""
Reputation Analysis Agent.
Checks URLs and domains against threat feeds and WHOIS data.
"""

import asyncio
from typing import Dict, List, Any
from datetime import datetime
import whois
from feeds.threat_feeds import get_threat_feed_client


class ReputationAgent:
    """Specialist agent for domain and URL reputation analysis."""
    
    def __init__(self):
        """Initialize reputation agent with threat feed client."""
        self.threat_client = get_threat_feed_client()
    
    async def _check_domain_age(self, domain: str) -> tuple[bool, List[str]]:
        """
        Check domain age using WHOIS.
        
        Args:
            domain: Domain to check
            
        Returns:
            Tuple of (is_suspicious, signals)
        """
        signals = []
        is_suspicious = False
        
        try:
            # Run WHOIS in thread pool to avoid blocking, with a hard timeout
            loop = asyncio.get_event_loop()
            domain_info = await asyncio.wait_for(
                loop.run_in_executor(None, whois.whois, domain),
                timeout=3.0
            )
            
            if domain_info and domain_info.creation_date:
                # Handle both single date and list of dates
                creation_date = domain_info.creation_date
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                # Calculate age in days
                age_days = (datetime.now() - creation_date).days
                
                if age_days < 30:
                    is_suspicious = True
                    signals.append(f"Very new domain (registered {age_days} days ago)")
                elif age_days < 90:
                    signals.append(f"Recently registered domain ({age_days} days old)")
        
        except Exception as e:
            # WHOIS lookup failed - not necessarily suspicious
            signals.append("Domain age could not be determined")
        
        return is_suspicious, signals
    
    async def _check_url_reputation(self, url: str) -> tuple[int, List[str]]:
        """
        Check URL against threat feeds.
        
        Args:
            url: URL to check
            
        Returns:
            Tuple of (score_addition, signals)
        """
        try:
            feed_results = await self.threat_client.check_all_feeds(url)
            
            if feed_results["is_malicious"]:
                return 50, feed_results["reasons"]
            
            return 0, []
        
        except Exception as e:
            return 0, [f"Threat feed check failed: {str(e)}"]
    
    async def analyze(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze domain and URL reputation.
        
        Args:
            payload: Email payload with URLs and sender info
            
        Returns:
            Agent result with score and signals
        """
        urls = payload.get("urls", [])
        sender = payload.get("sender", "")
        
        score = 0
        signals = []
        
        # Extract sender domain
        sender_domain = ""
        if sender and "@" in sender:
            sender_domain = sender.split("@")[1]
        
        # Run domain age check and URL reputation checks in parallel
        tasks = []
        if sender_domain:
            tasks.append(self._check_domain_age(sender_domain))
        url_tasks_start = len(tasks)
        if urls:
            tasks.extend([self._check_url_reputation(url) for url in urls[:5]])

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            results = []

        # Process domain age result
        if sender_domain and results:
            domain_result = results[0]
            if not isinstance(domain_result, Exception):
                domain_suspicious, domain_signals = domain_result
                if domain_suspicious:
                    score += 20
                signals.extend(domain_signals)

        # Process URL reputation results
        max_url_score = 0
        for result in results[url_tasks_start:]:
            if isinstance(result, Exception):
                continue
            url_score, url_signals = result
            max_url_score = max(max_url_score, url_score)
            signals.extend(url_signals)
        score += max_url_score
        
        # Normalize score
        score = min(score, 100)
        
        if not signals:
            signals = ["No reputation issues detected"]
        
        return {
            "score": score,
            "signals": signals[:10]  # Limit to top 10
        }


def get_reputation_agent() -> ReputationAgent:
    """
    Get reputation agent instance.
    
    Returns:
        ReputationAgent instance
    """
    return ReputationAgent()
