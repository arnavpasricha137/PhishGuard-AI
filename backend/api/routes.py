"""
FastAPI routes for PhishGuard AI backend.
"""

from fastapi import APIRouter, HTTPException, status
from api.models import (
    AnalyzeRequest,
    AnalyzeResponse,
    HealthResponse,
    CachedVerdictResponse
)
from agents.orchestrator import get_orchestrator
from cache.redis_client import redis_client

router = APIRouter()


@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    summary="Analyze email for phishing",
    description="Analyzes email content, URLs, and headers using multi-agent system"
)
async def analyze_email(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    Analyze an email for phishing indicators.
    
    Runs 4 specialist agents in parallel:
    - URL Agent: Analyzes all URLs for suspicious patterns
    - Content Agent: NLP analysis of email body
    - Header Agent: Email authentication and spoofing checks
    - Reputation Agent: Threat feed and domain reputation checks
    
    Returns combined verdict with detailed explanations.
    """
    try:
        # Convert request to payload dict
        payload = request.dict()
        
        # Get orchestrator and run analysis
        orchestrator = get_orchestrator()
        result = await orchestrator.analyze_email(payload)
        
        return AnalyzeResponse(**result)
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Analysis failed: {str(e)}"
        )


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Check backend health and service status"
)
async def health_check() -> HealthResponse:
    """
    Check health of backend services.
    
    Returns status of:
    - Overall system
    - Redis cache connection
    - Agent system readiness
    """
    try:
        # Check Redis
        redis_healthy = await redis_client.health_check()
        redis_status = "connected" if redis_healthy else "disconnected"
        
        # Check agents (basic check - orchestrator exists)
        try:
            orchestrator = get_orchestrator()
            agents_status = "ready"
        except Exception:
            agents_status = "error"
        
        # Overall status
        overall_status = "ok" if redis_healthy and agents_status == "ready" else "degraded"
        
        return HealthResponse(
            status=overall_status,
            redis=redis_status,
            agents=agents_status
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Health check failed: {str(e)}"
        )


@router.get(
    "/verdict/{url_hash}",
    response_model=CachedVerdictResponse,
    summary="Get cached URL verdict",
    description="Retrieve cached verdict for a URL by its MD5 hash"
)
async def get_cached_verdict(url_hash: str) -> CachedVerdictResponse:
    """
    Get cached verdict for a URL.
    
    Args:
        url_hash: MD5 hash of the URL
        
    Returns:
        Cached verdict if found
        
    Raises:
        404: If verdict not found in cache
    """
    try:
        # Look up by hash
        cached = await redis_client.get_verdict_by_hash(url_hash)
        
        if not cached:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Verdict not found in cache"
            )
        
        return CachedVerdictResponse(**cached, cached=True)
    
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Cache lookup failed: {str(e)}"
        )
