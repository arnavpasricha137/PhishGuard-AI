"""
Configuration management for PhishGuard AI Backend.
Loads and validates environment variables with sensible defaults.
"""

import os
from typing import List
from pydantic_settings import BaseSettings
from pydantic import Field, validator


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    redis_url: str = Field(
        default="redis://localhost:6379",
        description="Redis connection URL for caching"
    )
    
    phishtank_api_key: str = Field(
        default="",
        description="PhishTank API key for threat intelligence"
    )
    
    backend_port: int = Field(
        default=8000,
        description="Port for FastAPI server"
    )
    
    cors_origins: str = Field(
        default="chrome-extension://*,http://localhost:3000",
        description="Comma-separated list of allowed CORS origins"
    )
    
    log_level: str = Field(
        default="INFO",
        description="Logging level (DEBUG, INFO, WARNING, ERROR)"
    )
    
    agent_timeout: int = Field(
        default=5,
        description="Timeout in seconds for individual agent execution"
    )
    
    cache_ttl: int = Field(
        default=86400,
        description="Cache TTL in seconds (default 24 hours)"
    )
    
    model_name: str = Field(
        default="ealvaradob/bert-finetuned-phishing",
        description="HuggingFace model for phishing text classification"
    )
    
    max_workers: int = Field(
        default=4,
        description="Maximum number of concurrent workers"
    )
    
    urlhaus_api_url: str = Field(
        default="https://urlhaus-api.abuse.ch/v1/url/",
        description="URLhaus API endpoint"
    )
    
    phishtank_api_url: str = Field(
        default="https://checkurl.phishtank.com/checkurl/",
        description="PhishTank API endpoint"
    )
    
    external_api_timeout: int = Field(
        default=3,
        description="Timeout for external API calls in seconds"
    )
    
    @validator("cors_origins")
    def parse_cors_origins(cls, v: str) -> List[str]:
        """Parse comma-separated CORS origins into a list."""
        return [origin.strip() for origin in v.split(",") if origin.strip()]
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


def get_settings() -> Settings:
    """
    Get application settings singleton.
    Validates all required environment variables on first call.
    """
    return Settings()


# Validate settings on module import
settings = get_settings()

# Validate critical settings
if not settings.redis_url:
    raise ValueError("REDIS_URL environment variable is required")

print(f"✓ Configuration loaded successfully")
print(f"  - Redis: {settings.redis_url}")
print(f"  - Backend Port: {settings.backend_port}")
print(f"  - Log Level: {settings.log_level}")
print(f"  - Agent Timeout: {settings.agent_timeout}s")
print(f"  - Cache TTL: {settings.cache_ttl}s")
