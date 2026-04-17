"""
Threat intelligence feed integration.
Queries PhishTank and URLhaus for URL reputation.
"""

import asyncio
from typing import Dict, Optional, Tuple
import httpx
from config import settings


class ThreatFeedClient:
    """Async client for threat intelligence feeds."""
    
    def __init__(self):
        """Initialize threat feed client."""
        self.phishtank_url = settings.phishtank_api_url
        self.urlhaus_url = settings.urlhaus_api_url
        self.api_key = settings.phishtank_api_key
        self.timeout = settings.external_api_timeout
    
    async def check_phishtank(self, url: str) -> Tuple[bool, Optional[str]]:
        """
        Check URL against PhishTank database.
        
        Args:
            url: URL to check
            
        Returns:
            Tuple of (is_phishing, reason_or_none)
        """
        if not self.api_key:
            return False, None
        
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.phishtank_url,
                    data={
                        "url": url,
                        "format": "json",
                        "app_key": self.api_key
                    }
                )
                
                if response.status_code == 200:
                    data = response.json()
                    results = data.get("results", {})
                    
                    if results.get("in_database"):
                        is_valid = results.get("valid", False)
                        if is_valid:
                            return True, "URL found in PhishTank database as phishing"
                
                return False, None
        
        except (httpx.TimeoutException, httpx.RequestError) as e:
            print(f"PhishTank API error: {e}")
            return False, None
        except Exception as e:
            print(f"PhishTank unexpected error: {e}")
            return False, None
    
    async def check_urlhaus(self, url: str) -> Tuple[bool, Optional[str]]:
        """
        Check URL against URLhaus database.
        
        Args:
            url: URL to check
            
        Returns:
            Tuple of (is_malicious, reason_or_none)
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    self.urlhaus_url,
                    data={"url": url}
                )
                
                if response.status_code == 200:
                    data = response.json()
                    query_status = data.get("query_status")
                    
                    if query_status == "ok":
                        threat = data.get("threat", "unknown")
                        return True, f"URL found in URLhaus as {threat}"
                
                return False, None
        
        except (httpx.TimeoutException, httpx.RequestError) as e:
            print(f"URLhaus API error: {e}")
            return False, None
        except Exception as e:
            print(f"URLhaus unexpected error: {e}")
            return False, None
    
    async def check_all_feeds(self, url: str) -> Dict[str, any]:
        """
        Check URL against all threat feeds in parallel.
        
        Args:
            url: URL to check
            
        Returns:
            Dictionary with results from all feeds
        """
        # Run both checks in parallel
        phishtank_task = self.check_phishtank(url)
        urlhaus_task = self.check_urlhaus(url)
        
        phishtank_result, urlhaus_result = await asyncio.gather(
            phishtank_task,
            urlhaus_task,
            return_exceptions=True
        )
        
        # Handle exceptions
        if isinstance(phishtank_result, Exception):
            phishtank_result = (False, None)
        if isinstance(urlhaus_result, Exception):
            urlhaus_result = (False, None)
        
        phishtank_is_phishing, phishtank_reason = phishtank_result
        urlhaus_is_malicious, urlhaus_reason = urlhaus_result
        
        # Aggregate results
        is_malicious = phishtank_is_phishing or urlhaus_is_malicious
        reasons = []
        
        if phishtank_reason:
            reasons.append(phishtank_reason)
        if urlhaus_reason:
            reasons.append(urlhaus_reason)
        
        return {
            "is_malicious": is_malicious,
            "reasons": reasons,
            "phishtank_hit": phishtank_is_phishing,
            "urlhaus_hit": urlhaus_is_malicious
        }


# Global threat feed client
_client = None


def get_threat_feed_client() -> ThreatFeedClient:
    """
    Get or create global threat feed client instance.
    
    Returns:
        ThreatFeedClient instance
    """
    global _client
    if _client is None:
        _client = ThreatFeedClient()
    return _client
