"""
Pydantic models for API request/response validation.
"""

from typing import List, Dict, Optional
from pydantic import BaseModel, Field, validator


class AnalyzeRequest(BaseModel):
    """Request model for email analysis."""
    
    email_text: Optional[str] = Field(
        default="",
        description="Plain text email body"
    )
    
    email_html: Optional[str] = Field(
        default="",
        description="HTML email body"
    )
    
    subject: Optional[str] = Field(
        default="",
        description="Email subject line"
    )
    
    sender: Optional[str] = Field(
        default="",
        description="Sender email address"
    )
    
    reply_to: Optional[str] = Field(
        default="",
        description="Reply-To email address"
    )
    
    headers: Dict[str, str] = Field(
        default_factory=dict,
        description="Email headers as key-value pairs"
    )
    
    urls: List[str] = Field(
        default_factory=list,
        description="List of URLs found in email"
    )
    
    recipient_name: Optional[str] = Field(
        default="",
        description="Recipient's name for spear phishing detection"
    )
    
    @validator("urls", pre=True)
    def ensure_urls_list(cls, v):
        """Ensure URLs is always a list."""
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        return v
    
    class Config:
        schema_extra = {
            "example": {
                "email_text": "Dear customer, your account has been suspended. Click here to verify.",
                "subject": "Account Suspended",
                "sender": "security@paypal-verify.com",
                "urls": ["http://paypal-verify.com/login"],
                "recipient_name": "John"
            }
        }


class HighlightedPhrase(BaseModel):
    """Model for highlighted suspicious phrases."""
    
    text: str = Field(description="Exact phrase from email")
    reason: str = Field(description="Why this phrase is suspicious")
    severity: str = Field(description="Severity level: LOW, MEDIUM, HIGH")


class URLVerdict(BaseModel):
    """Model for individual URL analysis result."""
    
    url: str = Field(description="Analyzed URL")
    score: int = Field(description="Risk score 0-100")
    verdict: str = Field(description="SAFE, SUSPICIOUS, or PHISHING")
    signals: List[str] = Field(description="List of detected issues")


class AgentScore(BaseModel):
    """Model for individual agent score."""
    
    score: int = Field(description="Agent risk score 0-100")
    signals: List[str] = Field(description="Top signals from this agent")


class AnalyzeResponse(BaseModel):
    """Response model for email analysis."""
    
    verdict: str = Field(
        description="Final verdict: SAFE, SUSPICIOUS, or PHISHING"
    )
    
    confidence: float = Field(
        description="Confidence score 0.0-1.0"
    )
    
    final_score: int = Field(
        description="Final risk score 0-100"
    )
    
    agent_scores: Dict[str, AgentScore] = Field(
        description="Individual agent scores and signals"
    )
    
    url_verdicts: List[URLVerdict] = Field(
        description="Analysis results for each URL"
    )
    
    highlighted_phrases: List[HighlightedPhrase] = Field(
        description="Suspicious phrases found in email body"
    )
    
    spear_phishing_detected: bool = Field(
        description="Whether personalized attack was detected"
    )
    
    campaign_signature: Optional[str] = Field(
        default=None,
        description="Campaign signature if part of known campaign"
    )
    
    processing_time_ms: int = Field(
        description="Processing time in milliseconds"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "verdict": "PHISHING",
                "confidence": 0.87,
                "final_score": 87,
                "agent_scores": {
                    "url_agent": {
                        "score": 85,
                        "signals": ["Brand spoofing detected", "Missing HTTPS"]
                    },
                    "content_agent": {
                        "score": 78,
                        "signals": ["Credential harvesting phrase detected"]
                    },
                    "header_agent": {
                        "score": 60,
                        "signals": ["SPF validation failed"]
                    },
                    "reputation_agent": {
                        "score": 50,
                        "signals": ["URL found in PhishTank database"]
                    }
                },
                "url_verdicts": [
                    {
                        "url": "http://paypal-verify.com/login",
                        "score": 85,
                        "verdict": "PHISHING",
                        "signals": ["Brand spoofing detected", "Missing HTTPS"]
                    }
                ],
                "highlighted_phrases": [
                    {
                        "text": "verify your account",
                        "reason": "Credential harvesting attempt detected",
                        "severity": "HIGH"
                    }
                ],
                "spear_phishing_detected": False,
                "campaign_signature": None,
                "processing_time_ms": 1250
            }
        }


class HealthResponse(BaseModel):
    """Response model for health check."""
    
    status: str = Field(description="Overall status")
    redis: str = Field(description="Redis connection status")
    agents: str = Field(description="Agent system status")
    
    class Config:
        schema_extra = {
            "example": {
                "status": "ok",
                "redis": "connected",
                "agents": "ready"
            }
        }


class CachedVerdictResponse(BaseModel):
    """Response model for cached verdict lookup."""
    
    url: str = Field(description="Original URL")
    score: int = Field(description="Risk score 0-100")
    verdict: str = Field(description="SAFE, SUSPICIOUS, or PHISHING")
    signals: List[str] = Field(description="List of detected issues")
    cached: bool = Field(default=True, description="Whether result is from cache")
