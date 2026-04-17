"""
Redis client for caching URL verdicts and analysis results.
Provides async interface with automatic connection management.
"""

import json
import hashlib
from typing import Optional, Dict, Any
import redis.asyncio as redis
from redis.asyncio import Redis
from config import settings


class RedisClient:
    """Async Redis client for verdict caching."""
    
    def __init__(self):
        """Initialize Redis client with connection pool."""
        self._client: Optional[Redis] = None
        self._pool: Optional[redis.ConnectionPool] = None
    
    async def connect(self) -> None:
        """Establish Redis connection with connection pooling."""
        if self._client is None:
            self._pool = redis.ConnectionPool.from_url(
                settings.redis_url,
                decode_responses=True,
                max_connections=10
            )
            self._client = redis.Redis(connection_pool=self._pool)
            
            # Test connection
            try:
                await self._client.ping()
                print("✓ Redis connection established")
            except Exception as e:
                print(f"✗ Redis connection failed: {e}")
                raise
    
    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._pool:
            await self._pool.aclose()
            self._client = None
            self._pool = None
    
    @staticmethod
    def _hash_url(url: str) -> str:
        """
        Generate MD5 hash of URL for cache key.
        
        Args:
            url: URL to hash
            
        Returns:
            MD5 hash as hex string
        """
        return hashlib.md5(url.encode('utf-8')).hexdigest()
    
    async def get_verdict(self, url: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached verdict for a URL.
        
        Args:
            url: URL to look up
            
        Returns:
            Cached verdict dict or None if not found
        """
        if not self._client:
            await self.connect()
        
        url_hash = self._hash_url(url)
        cache_key = f"verdict:{url_hash}"
        
        try:
            cached = await self._client.get(cache_key)
            if cached:
                return json.loads(cached)
            return None
        except Exception as e:
            print(f"Redis get error: {e}")
            return None
    
    async def set_verdict(
        self, 
        url: str, 
        verdict: Dict[str, Any],
        ttl: Optional[int] = None
    ) -> bool:
        """
        Cache a URL verdict with TTL.
        
        Args:
            url: URL being cached
            verdict: Verdict dictionary to cache
            ttl: Time-to-live in seconds (default from settings)
            
        Returns:
            True if cached successfully, False otherwise
        """
        if not self._client:
            await self.connect()
        
        url_hash = self._hash_url(url)
        cache_key = f"verdict:{url_hash}"
        ttl = ttl or settings.cache_ttl
        
        try:
            await self._client.setex(
                cache_key,
                ttl,
                json.dumps(verdict)
            )
            return True
        except Exception as e:
            print(f"Redis set error: {e}")
            return False
    
    async def get_verdict_by_hash(self, url_hash: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached verdict by URL hash.
        
        Args:
            url_hash: MD5 hash of the URL
            
        Returns:
            Cached verdict dict or None if not found
        """
        if not self._client:
            await self.connect()
        
        cache_key = f"verdict:{url_hash}"
        
        try:
            cached = await self._client.get(cache_key)
            if cached:
                return json.loads(cached)
            return None
        except Exception as e:
            print(f"Redis get error: {e}")
            return None
    
    async def health_check(self) -> bool:
        """
        Check if Redis is connected and responsive.
        
        Returns:
            True if Redis is healthy, False otherwise
        """
        try:
            if not self._client:
                await self.connect()
            await self._client.ping()
            return True
        except Exception:
            return False


# Global Redis client instance
redis_client = RedisClient()


async def get_redis_client() -> RedisClient:
    """
    Dependency injection function for FastAPI.
    
    Returns:
        Connected Redis client instance
    """
    if not redis_client._client:
        await redis_client.connect()
    return redis_client
