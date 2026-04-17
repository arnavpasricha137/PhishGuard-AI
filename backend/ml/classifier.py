"""
DistilBERT-based phishing text classifier.
Uses pre-trained model fine-tuned on phishing detection.
"""

import re
from typing import Dict, Tuple
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
from config import settings


class PhishingClassifier:
    """DistilBERT classifier for phishing text detection."""
    
    def __init__(self):
        """Initialize tokenizer and model."""
        self.model_name = settings.model_name
        self.tokenizer = None
        self.model = None
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self._loaded = False
    
    def load_model(self) -> None:
        """Load the pre-trained model and tokenizer."""
        if self._loaded:
            return
        
        print(f"Loading model: {self.model_name}")
        try:
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name
            )
            self.model.to(self.device)
            self.model.eval()
            self._loaded = True
            print(f"✓ Model loaded on {self.device}")
        except Exception as e:
            print(f"✗ Model loading failed: {e}")
            print("  Falling back to rule-based detection")
            self._loaded = False
    
    @staticmethod
    def clean_text(text: str) -> str:
        """
        Clean and normalize text for classification.
        
        Args:
            text: Raw text input
            
        Returns:
            Cleaned text
        """
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', ' ', text)
        
        # Remove URLs (keep for context but simplify)
        text = re.sub(r'http[s]?://\S+', '[URL]', text)
        
        # Remove email addresses
        text = re.sub(r'\S+@\S+', '[EMAIL]', text)
        
        # Remove excessive whitespace
        text = re.sub(r'\s+', ' ', text)
        
        # Remove special characters but keep punctuation
        text = re.sub(r'[^\w\s.,!?@\-]', '', text)
        
        return text.strip()
    
    def predict(self, text: str) -> Tuple[float, int]:
        """
        Predict phishing probability for given text.
        
        Args:
            text: Email body text
            
        Returns:
            Tuple of (probability, confidence_score_0_100)
        """
        if not self._loaded:
            self.load_model()
        
        # Fallback to rule-based if model failed to load
        if not self._loaded or self.model is None:
            return self._rule_based_predict(text)
        
        # Clean and tokenize
        cleaned_text = self.clean_text(text)
        
        if not cleaned_text:
            return 0.0, 0
        
        try:
            # Tokenize
            inputs = self.tokenizer(
                cleaned_text,
                return_tensors="pt",
                truncation=True,
                max_length=512,
                padding=True
            )
            
            # Move to device
            inputs = {k: v.to(self.device) for k, v in inputs.items()}
            
            # Inference
            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probabilities = torch.softmax(logits, dim=1)
                
                # Assuming binary classification: [safe, phishing]
                phishing_prob = probabilities[0][1].item()
                confidence_score = int(phishing_prob * 100)
                
                return phishing_prob, confidence_score
        
        except Exception as e:
            print(f"Prediction error: {e}")
            return self._rule_based_predict(text)
    
    @staticmethod
    def _rule_based_predict(text: str) -> Tuple[float, int]:
        """
        Fallback rule-based prediction when ML model unavailable.
        
        Args:
            text: Email body text
            
        Returns:
            Tuple of (probability, confidence_score_0_100)
        """
        text_lower = text.lower()
        score = 0
        
        # High-risk keywords
        high_risk = [
            "verify your account", "confirm your identity", 
            "reset your password", "suspended", "unusual activity"
        ]
        for keyword in high_risk:
            if keyword in text_lower:
                score += 18
        
        # Medium-risk keywords
        medium_risk = [
            "urgent", "immediately", "click here", "login now",
            "update your account", "act now", "limited time"
        ]
        for keyword in medium_risk:
            if keyword in text_lower:
                score += 12
        
        # Credential harvesting
        if any(phrase in text_lower for phrase in [
            "enter your password", "share your otp", 
            "verify your bank", "confirm card details"
        ]):
            score += 25
        
        # Urgency patterns
        if re.search(r'within \d+ (hours|minutes)', text_lower):
            score += 15
        
        # Generic greetings
        if any(greeting in text_lower for greeting in [
            "dear customer", "dear user", "dear account holder"
        ]):
            score += 10
        
        # Normalize to 0-100
        score = min(score, 100)
        probability = score / 100.0
        
        return probability, score


# Global classifier instance
_classifier = None


def get_classifier() -> PhishingClassifier:
    """
    Get or create global classifier instance.
    
    Returns:
        PhishingClassifier instance
    """
    global _classifier
    if _classifier is None:
        _classifier = PhishingClassifier()
        _classifier.load_model()
    return _classifier
