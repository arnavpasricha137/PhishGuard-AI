"""Multi-agent system for phishing detection."""

from .url_agent import get_url_agent, URLAgent
from .content_agent import get_content_agent, ContentAgent
from .header_agent import get_header_agent, HeaderAgent
from .reputation_agent import get_reputation_agent, ReputationAgent

__all__ = [
    "get_url_agent",
    "URLAgent",
    "get_content_agent",
    "ContentAgent",
    "get_header_agent",
    "HeaderAgent",
    "get_reputation_agent",
    "ReputationAgent",
]
