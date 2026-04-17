"""
PhishGuard AI Backend - Main FastAPI Application.
Multi-agent phishing detection system with Redis caching.
"""

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from config import settings
from cache.redis_client import redis_client
from api.routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager.
    Handles startup and shutdown events.
    """
    # Startup
    print("=" * 60)
    print("🛡️  PhishGuard AI Backend Starting...")
    print("=" * 60)
    
    # Connect to Redis
    try:
        await redis_client.connect()
        print("✓ Redis connected")
    except Exception as e:
        print(f"✗ Redis connection failed: {e}")
        print("  Continuing without cache...")
    
    # Load ML models (lazy loading on first use)
    print("✓ ML models will load on first request")
    
    print("=" * 60)
    print(f"🚀 Server ready on http://localhost:{settings.backend_port}")
    print("=" * 60)
    
    yield
    
    # Shutdown
    print("\n" + "=" * 60)
    print("🛑 PhishGuard AI Backend Shutting Down...")
    print("=" * 60)
    
    await redis_client.disconnect()
    print("✓ Redis disconnected")
    print("✓ Cleanup complete")


# Create FastAPI app
app = FastAPI(
    title="PhishGuard AI",
    description="Multi-agent phishing detection system with ML and threat intelligence",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routes
app.include_router(router, prefix="", tags=["analysis"])


@app.get("/", tags=["root"])
async def root():
    """Root endpoint with API information."""
    return {
        "name": "PhishGuard AI Backend",
        "version": "1.0.0",
        "status": "running",
        "docs": "/docs",
        "endpoints": {
            "analyze": "POST /analyze",
            "health": "GET /health",
            "cached_verdict": "GET /verdict/{url_hash}"
        }
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=settings.backend_port,
        reload=True,
        log_level=settings.log_level.lower()
    )
