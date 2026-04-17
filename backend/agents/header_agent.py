"""
Header Analysis Agent.
Analyzes email headers for authentication failures and spoofing indicators.
"""

import re
from typing import Dict, List, Any
from ml.brand_detector import get_brand_detector


class HeaderAgent:
    """Specialist agent for email header analysis."""
    
    def __init__(self):
        """Initialize header agent with brand detector."""
        self.brand_detector = get_brand_detector()
    
    def _parse_spf(self, headers: Dict[str, str]) -> tuple[bool, List[str]]:
        """
        Parse SPF validation from headers.
        
        Args:
            headers: Email headers dictionary
            
        Returns:
            Tuple of (has_issue, signals)
        """
        signals = []
        has_issue = False
        
        # Check Received-SPF header
        spf_header = headers.get("Received-SPF", "").lower()
        
        if not spf_header:
            # Check Authentication-Results for SPF
            auth_results = headers.get("Authentication-Results", "").lower()
            if "spf=" in auth_results:
                if "spf=fail" in auth_results:
                    has_issue = True
                    signals.append("SPF validation failed")
                elif "spf=softfail" in auth_results:
                    has_issue = True
                    signals.append("SPF soft-fail detected")
                elif "spf=none" in auth_results:
                    signals.append("No SPF record found")
        else:
            if "fail" in spf_header:
                has_issue = True
                signals.append("SPF validation failed")
            elif "softfail" in spf_header:
                has_issue = True
                signals.append("SPF soft-fail detected")
            elif "none" in spf_header:
                signals.append("No SPF record found")
        
        return has_issue, signals
    
    def _parse_dkim(self, headers: Dict[str, str]) -> tuple[bool, List[str]]:
        """
        Parse DKIM validation from headers.
        
        Args:
            headers: Email headers dictionary
            
        Returns:
            Tuple of (has_issue, signals)
        """
        signals = []
        has_issue = False
        
        # Check DKIM-Signature header
        dkim_signature = headers.get("DKIM-Signature", "")
        
        if not dkim_signature:
            signals.append("No DKIM signature found")
            has_issue = True
        else:
            # Check Authentication-Results for DKIM validation
            auth_results = headers.get("Authentication-Results", "").lower()
            if "dkim=" in auth_results:
                if "dkim=fail" in auth_results:
                    has_issue = True
                    signals.append("DKIM validation failed")
                elif "dkim=none" in auth_results:
                    has_issue = True
                    signals.append("DKIM signature not validated")
        
        return has_issue, signals
    
    def _parse_dmarc(self, headers: Dict[str, str]) -> tuple[bool, List[str]]:
        """
        Parse DMARC validation from headers.
        
        Args:
            headers: Email headers dictionary
            
        Returns:
            Tuple of (has_issue, signals)
        """
        signals = []
        has_issue = False
        
        auth_results = headers.get("Authentication-Results", "").lower()
        
        if "dmarc=" in auth_results:
            if "dmarc=fail" in auth_results:
                has_issue = True
                signals.append("DMARC validation failed")
            elif "dmarc=none" in auth_results:
                signals.append("No DMARC policy found")
        
        return has_issue, signals
    
    def _check_reply_to_mismatch(
        self, 
        sender: str, 
        reply_to: str
    ) -> tuple[bool, List[str]]:
        """
        Check if Reply-To domain differs from sender domain.
        
        Args:
            sender: Sender email address
            reply_to: Reply-To email address
            
        Returns:
            Tuple of (has_mismatch, signals)
        """
        signals = []
        has_mismatch = False
        
        if not sender or not reply_to:
            return False, []
        
        # Extract domains
        sender_domain = sender.split("@")[1] if "@" in sender else ""
        reply_to_domain = reply_to.split("@")[1] if "@" in reply_to else ""
        
        if sender_domain and reply_to_domain and sender_domain != reply_to_domain:
            has_mismatch = True
            signals.append(
                f"Reply-To domain mismatch: sender is {sender_domain}, "
                f"but replies go to {reply_to_domain}"
            )
        
        return has_mismatch, signals
    
    def _check_display_name_spoofing(
        self, 
        sender: str
    ) -> tuple[bool, List[str]]:
        """
        Check if sender display name contains brand but email doesn't match.
        
        Args:
            sender: Full sender string (e.g., "PayPal <fake@evil.com>")
            
        Returns:
            Tuple of (is_spoofing, signals)
        """
        signals = []
        is_spoofing = False
        
        # Parse display name and email
        match = re.match(r'^(.+?)\s*<(.+?)>$', sender)
        if match:
            display_name = match.group(1).strip()
            email = match.group(2).strip()
            
            # Extract domain from email
            email_domain = email.split("@")[1] if "@" in email else ""
            
            if email_domain:
                is_spoofing, spoof_signals = self.brand_detector.detect_display_name_spoofing(
                    display_name,
                    email_domain
                )
                signals.extend(spoof_signals)
        
        return is_spoofing, signals
    
    async def analyze(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze email headers for authentication and spoofing issues.
        
        Args:
            payload: Email payload with headers and metadata
            
        Returns:
            Agent result with score and signals
        """
        headers = payload.get("headers", {})
        sender = payload.get("sender", "")
        reply_to = payload.get("reply_to", "")
        
        score = 0
        signals = []
        
        # Check SPF
        spf_issue, spf_signals = self._parse_spf(headers)
        if spf_issue:
            score += 20
        signals.extend(spf_signals)
        
        # Check DKIM
        dkim_issue, dkim_signals = self._parse_dkim(headers)
        if dkim_issue:
            score += 20
        signals.extend(dkim_signals)
        
        # Check DMARC
        dmarc_issue, dmarc_signals = self._parse_dmarc(headers)
        if dmarc_issue:
            score += 15
        signals.extend(dmarc_signals)
        
        # Check Reply-To mismatch
        reply_mismatch, reply_signals = self._check_reply_to_mismatch(sender, reply_to)
        if reply_mismatch:
            score += 25
        signals.extend(reply_signals)
        
        # Check display name spoofing
        display_spoof, display_signals = self._check_display_name_spoofing(sender)
        if display_spoof:
            score += 30
        signals.extend(display_signals)
        
        # Normalize score
        score = min(score, 100)
        
        if not signals:
            signals = ["Email headers appear legitimate"]
        
        return {
            "score": score,
            "signals": signals[:10]  # Limit to top 10
        }


def get_header_agent() -> HeaderAgent:
    """
    Get header agent instance.
    
    Returns:
        HeaderAgent instance
    """
    return HeaderAgent()
