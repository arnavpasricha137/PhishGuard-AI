"""
URL feature extraction for phishing detection.
Extracts lexical, structural, and statistical features from URLs.
"""

import re
import math
from typing import Dict, List, Tuple
from urllib.parse import urlparse
from collections import Counter
import tldextract


class URLFeatureExtractor:
    """Extract features from URLs for phishing detection."""
    
    # Known URL shorteners
    SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", 
        "rb.gy", "cutt.ly", "ow.ly", "is.gd", "buff.ly"
    }
    
    # High-risk TLDs
    RISKY_TLDS = {
        "xyz", "top", "tk", "ml", "ga", "cf", "gq", 
        "work", "click", "link", "pw", "cc", "info"
    }
    
    # Suspicious keywords in URLs
    SUSPICIOUS_KEYWORDS = {
        "login", "verify", "secure", "update", "account",
        "banking", "signin", "confirm", "suspend", "unlock"
    }
    
    def __init__(self):
        """Initialize feature extractor."""
        pass
    
    def extract_all_features(self, url: str) -> Dict[str, any]:
        """
        Extract all features from a URL.
        
        Args:
            url: URL to analyze
            
        Returns:
            Dictionary of extracted features
        """
        parsed = self._parse_url(url)
        
        features = {
            # Basic structure
            "url_length": len(url),
            "domain_length": len(parsed["domain"]),
            "path_length": len(parsed["path"]),
            
            # Domain features
            "subdomain_count": parsed["subdomain_count"],
            "hyphen_count": parsed["domain"].count("-"),
            "dot_count": url.count("."),
            "digit_count": sum(c.isdigit() for c in parsed["domain"]),
            
            # Suspicious patterns
            "has_at_symbol": "@" in url,
            "has_ip_address": self._has_ip_address(parsed["domain"]),
            "is_shortener": parsed["domain"] in self.SHORTENERS,
            "risky_tld": parsed["tld"] in self.RISKY_TLDS,
            
            # Security
            "is_https": parsed["scheme"] == "https",
            "has_port": parsed["port"] is not None,
            
            # Statistical
            "entropy": self._calculate_entropy(parsed["domain"]),
            "consonant_ratio": self._consonant_ratio(parsed["domain"]),
            
            # Suspicious keywords
            "suspicious_keyword_count": self._count_suspicious_keywords(url),
            
            # Encoding
            "has_encoded_chars": "%" in url,
            "double_slash_in_path": "//" in parsed["path"],
            
            # Homoglyph detection
            "has_homoglyphs": self._detect_homoglyphs(parsed["domain"]),
            
            # TLD
            "tld": parsed["tld"],
            "domain": parsed["domain"],
            "full_domain": parsed["full_domain"]
        }
        
        return features
    
    @staticmethod
    def _parse_url(url: str) -> Dict[str, any]:
        """
        Parse URL into components.
        
        Args:
            url: URL to parse
            
        Returns:
            Dictionary of URL components
        """
        # Ensure URL has scheme
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        
        parsed = urlparse(url)
        extracted = tldextract.extract(url)
        
        subdomain_count = len(extracted.subdomain.split(".")) if extracted.subdomain else 0
        
        return {
            "scheme": parsed.scheme,
            "domain": extracted.domain,
            "subdomain": extracted.subdomain,
            "subdomain_count": subdomain_count,
            "tld": extracted.suffix,
            "full_domain": f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain,
            "path": parsed.path,
            "query": parsed.query,
            "port": parsed.port,
            "netloc": parsed.netloc
        }
    
    @staticmethod
    def _has_ip_address(domain: str) -> bool:
        """
        Check if domain is an IP address.
        
        Args:
            domain: Domain string
            
        Returns:
            True if domain is an IP address
        """
        ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        return bool(re.match(ip_pattern, domain))
    
    @staticmethod
    def _calculate_entropy(text: str) -> float:
        """
        Calculate Shannon entropy of text.
        
        Args:
            text: Text to analyze
            
        Returns:
            Entropy value
        """
        if not text:
            return 0.0
        
        # Count character frequencies
        counter = Counter(text)
        length = len(text)
        
        # Calculate entropy
        entropy = 0.0
        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def _consonant_ratio(text: str) -> float:
        """
        Calculate ratio of consonants to total letters.
        
        Args:
            text: Text to analyze
            
        Returns:
            Consonant ratio (0.0 to 1.0)
        """
        vowels = set("aeiouAEIOU")
        letters = [c for c in text if c.isalpha()]
        
        if not letters:
            return 0.0
        
        consonants = [c for c in letters if c not in vowels]
        return len(consonants) / len(letters)
    
    def _count_suspicious_keywords(self, url: str) -> int:
        """
        Count suspicious keywords in URL.
        
        Args:
            url: URL to analyze
            
        Returns:
            Count of suspicious keywords
        """
        url_lower = url.lower()
        return sum(1 for keyword in self.SUSPICIOUS_KEYWORDS if keyword in url_lower)
    
    @staticmethod
    def _detect_homoglyphs(domain: str) -> bool:
        """
        Detect potential homoglyph characters (Unicode lookalikes).
        
        Args:
            domain: Domain to check
            
        Returns:
            True if potential homoglyphs detected
        """
        # Check for non-ASCII characters
        try:
            domain.encode('ascii')
            return False
        except UnicodeEncodeError:
            # Contains non-ASCII characters - potential homoglyphs
            return True
    
    def calculate_risk_score(self, features: Dict[str, any]) -> Tuple[int, List[str]]:
        """
        Calculate risk score from extracted features.
        
        Args:
            features: Feature dictionary from extract_all_features
            
        Returns:
            Tuple of (score_0_100, list_of_reasons)
        """
        score = 0
        reasons = []
        
        # URL length
        if features["url_length"] > 75:
            score += 12
            reasons.append("Very long URL detected")
        
        # IP address instead of domain
        if features["has_ip_address"]:
            score += 20
            reasons.append("IP address used instead of domain name")
        
        # @ symbol
        if features["has_at_symbol"]:
            score += 25
            reasons.append("URL contains '@' symbol (obfuscation technique)")
        
        # URL shortener
        if features["is_shortener"]:
            score += 20
            reasons.append("Shortened URL detected")
        
        # Risky TLD
        if features["risky_tld"]:
            score += 15
            reasons.append(f"High-risk TLD detected: .{features['tld']}")
        
        # Excessive subdomains
        if features["subdomain_count"] >= 3:
            score += 10
            reasons.append("Too many subdomains detected")
        
        # Excessive hyphens
        if features["hyphen_count"] >= 2:
            score += 10
            reasons.append("Excessive hyphens in domain")
        
        # Missing HTTPS
        if not features["is_https"]:
            score += 10
            reasons.append("URL is not using HTTPS")
        
        # High entropy (random-looking domain)
        if features["entropy"] > 4.0:
            score += 8
            reasons.append("Domain appears randomly generated")
        
        # Suspicious keywords
        if features["suspicious_keyword_count"] > 0:
            score += features["suspicious_keyword_count"] * 7
            reasons.append(f"Suspicious keywords found in URL ({features['suspicious_keyword_count']})")
        
        # Encoded characters
        if features["has_encoded_chars"]:
            score += 8
            reasons.append("Encoded characters found in URL")
        
        # Double slash in path
        if features["double_slash_in_path"]:
            score += 8
            reasons.append("Unusual redirect-like path structure")
        
        # Homoglyphs
        if features["has_homoglyphs"]:
            score += 15
            reasons.append("Potential homoglyph characters detected (Unicode spoofing)")
        
        # Normalize score
        score = min(score, 100)
        
        if not reasons:
            reasons.append("No major URL anomalies detected")
        
        return score, reasons


# Global feature extractor instance
_extractor = None


def get_url_feature_extractor() -> URLFeatureExtractor:
    """
    Get or create global URL feature extractor instance.
    
    Returns:
        URLFeatureExtractor instance
    """
    global _extractor
    if _extractor is None:
        _extractor = URLFeatureExtractor()
    return _extractor
