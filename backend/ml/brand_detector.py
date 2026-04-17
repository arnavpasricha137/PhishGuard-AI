"""
Brand impersonation detection for phishing URLs and content.
Detects when brand names appear in suspicious contexts.
"""

from typing import List, Tuple, Dict
import re


class BrandDetector:
    """Detect brand impersonation attempts in URLs and text."""
    
    # Major brands with their official domains
    BRANDS = {
        "paypal": ["paypal.com", "paypal.me"],
        "amazon": ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.ca"],
        "google": ["google.com", "gmail.com", "youtube.com", "google.co.uk"],
        "microsoft": ["microsoft.com", "outlook.com", "live.com", "office.com", "xbox.com"],
        "apple": ["apple.com", "icloud.com", "me.com", "mac.com"],
        "facebook": ["facebook.com", "fb.com", "messenger.com"],
        "instagram": ["instagram.com"],
        "netflix": ["netflix.com"],
        "chase": ["chase.com", "jpmorganchase.com"],
        "wellsfargo": ["wellsfargo.com"],
        "bankofamerica": ["bankofamerica.com", "bofa.com"],
        "citibank": ["citibank.com", "citi.com"],
        "americanexpress": ["americanexpress.com", "amex.com"],
        "discover": ["discover.com", "discovercard.com"],
        "ebay": ["ebay.com"],
        "linkedin": ["linkedin.com"],
        "twitter": ["twitter.com", "x.com"],
        "dropbox": ["dropbox.com"],
        "adobe": ["adobe.com"],
        "spotify": ["spotify.com"],
        "coinbase": ["coinbase.com"],
        "binance": ["binance.com"],
        "walmart": ["walmart.com"],
        "target": ["target.com"],
        "bestbuy": ["bestbuy.com"],
        "fedex": ["fedex.com"],
        "ups": ["ups.com"],
        "usps": ["usps.com", "usps.gov"],
        "dhl": ["dhl.com"],
    }
    
    # Financial keywords that increase suspicion
    FINANCIAL_KEYWORDS = {
        "bank", "banking", "account", "credit", "debit", "card",
        "payment", "transaction", "transfer", "balance", "verify",
        "secure", "login", "signin", "password", "otp", "2fa"
    }
    
    def __init__(self):
        """Initialize brand detector."""
        # Create reverse mapping: official_domain -> brand_name
        self.domain_to_brand = {}
        for brand, domains in self.BRANDS.items():
            for domain in domains:
                self.domain_to_brand[domain] = brand
    
    def detect_url_spoofing(self, url: str, domain: str) -> Tuple[bool, List[str]]:
        """
        Detect if URL is spoofing a known brand.
        
        Args:
            url: Full URL
            domain: Extracted domain (e.g., "example.com")
            
        Returns:
            Tuple of (is_spoofing, list_of_reasons)
        """
        url_lower = url.lower()
        domain_lower = domain.lower()
        reasons = []
        is_spoofing = False
        
        # Check each brand
        for brand_name, official_domains in self.BRANDS.items():
            # Check if brand name appears in URL
            if brand_name in url_lower:
                # Check if domain is NOT an official domain
                is_official = any(
                    domain_lower.endswith(official_domain) 
                    for official_domain in official_domains
                )
                
                if not is_official:
                    is_spoofing = True
                    reasons.append(
                        f"Brand spoofing detected: '{brand_name}' appears in URL "
                        f"but domain '{domain}' is not official"
                    )
        
        return is_spoofing, reasons
    
    def detect_text_impersonation(
        self, 
        text: str, 
        sender_domain: str = None
    ) -> Tuple[bool, List[str]]:
        """
        Detect brand impersonation in email text.
        
        Args:
            text: Email body text
            sender_domain: Sender's email domain
            
        Returns:
            Tuple of (is_impersonating, list_of_reasons)
        """
        text_lower = text.lower()
        reasons = []
        is_impersonating = False
        
        # Check for brand mentions
        mentioned_brands = []
        for brand_name in self.BRANDS.keys():
            if brand_name in text_lower:
                mentioned_brands.append(brand_name)
        
        # If sender domain provided, check mismatch
        if sender_domain and mentioned_brands:
            sender_domain_lower = sender_domain.lower()
            
            for brand in mentioned_brands:
                official_domains = self.BRANDS[brand]
                is_official = any(
                    sender_domain_lower.endswith(official_domain)
                    for official_domain in official_domains
                )
                
                if not is_official:
                    # Check if financial keywords present
                    has_financial = any(
                        keyword in text_lower 
                        for keyword in self.FINANCIAL_KEYWORDS
                    )
                    
                    if has_financial:
                        is_impersonating = True
                        reasons.append(
                            f"Possible impersonation: Email mentions '{brand}' "
                            f"with financial keywords but sender domain is '{sender_domain}'"
                        )
        
        return is_impersonating, reasons
    
    def detect_display_name_spoofing(
        self, 
        display_name: str, 
        email_domain: str
    ) -> Tuple[bool, List[str]]:
        """
        Detect if sender display name contains brand but email doesn't match.
        
        Args:
            display_name: Sender's display name
            email_domain: Actual email domain
            
        Returns:
            Tuple of (is_spoofing, list_of_reasons)
        """
        display_lower = display_name.lower()
        domain_lower = email_domain.lower()
        reasons = []
        is_spoofing = False
        
        for brand_name, official_domains in self.BRANDS.items():
            if brand_name in display_lower:
                is_official = any(
                    domain_lower.endswith(official_domain)
                    for official_domain in official_domains
                )
                
                if not is_official:
                    is_spoofing = True
                    reasons.append(
                        f"Display name spoofing: Name contains '{brand_name}' "
                        f"but email domain is '{email_domain}'"
                    )
        
        return is_spoofing, reasons
    
    def get_brand_from_domain(self, domain: str) -> str:
        """
        Get brand name from official domain.
        
        Args:
            domain: Domain to check
            
        Returns:
            Brand name or empty string if not recognized
        """
        domain_lower = domain.lower()
        
        for official_domain, brand in self.domain_to_brand.items():
            if domain_lower.endswith(official_domain):
                return brand
        
        return ""


# Global brand detector instance
_detector = None


def get_brand_detector() -> BrandDetector:
    """
    Get or create global brand detector instance.
    
    Returns:
        BrandDetector instance
    """
    global _detector
    if _detector is None:
        _detector = BrandDetector()
    return _detector
