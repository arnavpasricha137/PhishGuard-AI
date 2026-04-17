"""
Content Analysis Agent.
Analyzes email body text using NLP and pattern matching for phishing indicators.
"""

import re
from typing import Dict, List, Any, Tuple
from ml.classifier import get_classifier
from ml.brand_detector import get_brand_detector


class ContentAgent:
    """Specialist agent for email content analysis."""
    
    # High severity phrases (credential harvesting)
    HIGH_SEVERITY_PHRASES = [
        "enter your password",
        "share your otp",
        "verify your bank details",
        "confirm card details",
        "provide your ssn",
        "enter your pin",
        "confirm your password",
        "update payment information",
        "verify payment method",
        "confirm billing information"
    ]
    
    # Medium severity phrases (urgency/social engineering)
    MEDIUM_SEVERITY_PHRASES = [
        "urgent action required",
        "immediate action required",
        "verify your account",
        "confirm your identity",
        "reset your password",
        "account suspended",
        "unusual activity",
        "suspicious activity",
        "account will be closed",
        "limited time offer",
        "act now",
        "click here immediately",
        "respond within"
    ]
    
    # Low severity phrases (mild indicators)
    LOW_SEVERITY_PHRASES = [
        "dear customer",
        "dear user",
        "dear account holder",
        "click here",
        "click the link",
        "free gift",
        "you've won",
        "claim your prize",
        "congratulations"
    ]
    
    def __init__(self):
        """Initialize content agent with classifier and brand detector."""
        self.classifier = get_classifier()
        self.brand_detector = get_brand_detector()
    
    def _extract_highlighted_phrases(self, text: str) -> List[Dict[str, str]]:
        """
        Extract suspicious phrases from text with severity levels.
        
        Args:
            text: Email body text
            
        Returns:
            List of highlighted phrase dictionaries
        """
        text_lower = text.lower()
        highlighted = []
        
        # Check high severity
        for phrase in self.HIGH_SEVERITY_PHRASES:
            if phrase in text_lower:
                # Find actual occurrence in original text
                pattern = re.compile(re.escape(phrase), re.IGNORECASE)
                match = pattern.search(text)
                if match:
                    highlighted.append({
                        "text": match.group(),
                        "reason": "Credential harvesting attempt detected",
                        "severity": "HIGH"
                    })
        
        # Check medium severity
        for phrase in self.MEDIUM_SEVERITY_PHRASES:
            if phrase in text_lower:
                pattern = re.compile(re.escape(phrase), re.IGNORECASE)
                match = pattern.search(text)
                if match:
                    highlighted.append({
                        "text": match.group(),
                        "reason": "Urgency-based social engineering language",
                        "severity": "MEDIUM"
                    })
        
        # Check low severity
        for phrase in self.LOW_SEVERITY_PHRASES:
            if phrase in text_lower:
                pattern = re.compile(re.escape(phrase), re.IGNORECASE)
                match = pattern.search(text)
                if match:
                    highlighted.append({
                        "text": match.group(),
                        "reason": "Generic or suspicious phrasing",
                        "severity": "LOW"
                    })
        
        # Remove duplicates (keep first occurrence)
        seen = set()
        unique_highlighted = []
        for item in highlighted:
            key = (item["text"].lower(), item["severity"])
            if key not in seen:
                seen.add(key)
                unique_highlighted.append(item)
        
        return unique_highlighted[:15]  # Limit to 15 phrases
    
    def _detect_urgency_patterns(self, text: str) -> List[str]:
        """
        Detect urgency patterns using regex.
        
        Args:
            text: Email body text
            
        Returns:
            List of detected urgency signals
        """
        signals = []
        text_lower = text.lower()
        
        patterns = [
            (r'within \d+ (hours?|minutes?|days?)', "Time-pressure tactic detected"),
            (r'(your account|access) will be (closed|suspended|terminated)', "Account threat detected"),
            (r'failure to (respond|act|verify)', "Compliance pressure detected"),
            (r'immediate(ly)? (action|response) (required|needed)', "Immediate action demand"),
        ]
        
        for pattern, message in patterns:
            if re.search(pattern, text_lower):
                signals.append(message)
        
        return signals
    
    def _detect_spear_phishing(
        self, 
        text: str, 
        recipient_name: str,
        sender_domain: str
    ) -> Tuple[bool, List[str]]:
        """
        Detect personalized spear phishing attempts.
        
        Args:
            text: Email body text
            recipient_name: Recipient's name
            sender_domain: Sender's email domain
            
        Returns:
            Tuple of (is_spear_phishing, reasons)
        """
        if not recipient_name:
            return False, []
        
        text_lower = text.lower()
        name_lower = recipient_name.lower()
        reasons = []
        is_spear = False
        
        # Check if recipient name appears in text
        if name_lower in text_lower:
            # Check for suspicious domain + personalization
            if sender_domain:
                # Check for brand impersonation
                is_impersonating, imperson_reasons = self.brand_detector.detect_text_impersonation(
                    text, 
                    sender_domain
                )
                
                if is_impersonating:
                    is_spear = True
                    reasons.append(
                        f"Personalized attack: Email addresses '{recipient_name}' "
                        f"while impersonating a brand"
                    )
            
            # Check for credential requests with personalization
            has_credential_request = any(
                phrase in text_lower 
                for phrase in self.HIGH_SEVERITY_PHRASES
            )
            
            if has_credential_request:
                is_spear = True
                reasons.append(
                    f"Targeted credential theft: Email addresses '{recipient_name}' "
                    f"and requests sensitive information"
                )
        
        return is_spear, reasons
    
    async def analyze(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze email content for phishing indicators.
        
        Args:
            payload: Email payload with text, HTML, and metadata
            
        Returns:
            Agent result with score, signals, and highlighted phrases
        """
        email_text = payload.get("email_text", "")
        email_html = payload.get("email_html", "")
        recipient_name = payload.get("recipient_name", "")
        sender = payload.get("sender", "")
        
        # Extract sender domain
        sender_domain = ""
        if sender and "@" in sender:
            sender_domain = sender.split("@")[1] if "@" in sender else ""
        
        # Use text if available, otherwise extract from HTML
        content = email_text or email_html
        
        if not content:
            return {
                "score": 0,
                "signals": ["No email content to analyze"],
                "highlighted_phrases": [],
                "spear_phishing_detected": False
            }
        
        # Run ML classifier
        ml_probability, ml_score = self.classifier.predict(content)
        
        # Extract highlighted phrases
        highlighted_phrases = self._extract_highlighted_phrases(content)
        
        # Detect urgency patterns
        urgency_signals = self._detect_urgency_patterns(content)
        
        # Detect spear phishing
        is_spear, spear_reasons = self._detect_spear_phishing(
            content,
            recipient_name,
            sender_domain
        )
        
        # Calculate final score
        score = ml_score
        signals = [f"ML classifier confidence: {ml_score}%"]
        
        # Add points for highlighted phrases
        high_count = sum(1 for p in highlighted_phrases if p["severity"] == "HIGH")
        medium_count = sum(1 for p in highlighted_phrases if p["severity"] == "MEDIUM")
        low_count = sum(1 for p in highlighted_phrases if p["severity"] == "LOW")
        
        phrase_score = (high_count * 20) + (medium_count * 10) + (low_count * 5)
        score = min(score + phrase_score, 100)
        
        if high_count > 0:
            signals.append(f"{high_count} credential harvesting phrase(s) detected")
        if medium_count > 0:
            signals.append(f"{medium_count} urgency/social engineering phrase(s) detected")
        if low_count > 0:
            signals.append(f"{low_count} suspicious phrase(s) detected")
        
        # Add urgency signals
        signals.extend(urgency_signals)
        
        # Add spear phishing signals
        if is_spear:
            score = min(score + 25, 100)
            signals.extend(spear_reasons)
        
        # Check for excessive punctuation
        exclamation_count = content.count("!")
        if exclamation_count >= 3:
            score = min(score + 8, 100)
            signals.append(f"Excessive punctuation detected ({exclamation_count} exclamation marks)")
        
        # Check for generic greetings
        content_lower = content.lower()
        generic_greetings = ["dear customer", "dear user", "dear account holder"]
        for greeting in generic_greetings:
            if greeting in content_lower:
                score = min(score + 8, 100)
                signals.append(f"Generic greeting detected: '{greeting}'")
                break
        
        return {
            "score": score,
            "signals": signals[:10],  # Limit to top 10
            "highlighted_phrases": highlighted_phrases,
            "spear_phishing_detected": is_spear
        }


def get_content_agent() -> ContentAgent:
    """
    Get content agent instance.
    
    Returns:
        ContentAgent instance
    """
    return ContentAgent()
