from utils.logger import get_logger
import time
from typing import Tuple, Dict, Any, Optional
from utils.errors import EnrichmentError, ErrorCode
import redis.asyncio as redis

logger = get_logger("rate_limiter")

class RateLimiter:
    def __init__(
        self,
        redis_client: redis.Redis,
        max_requests: int = 60,
        window_seconds: int = 60,
        burst_size: int = 10
    ):
        self.redis = redis_client
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.burst_size = burst_size

    async def check_limit(self, key: str, limit: int, window_seconds: int) -> bool:
        current_key = f"rate_limiter:{key}:{int(time.time() / window_seconds)}"
        try:
            async with self.redis.pipeline(transaction=True) as pipe:
                pipe.incr(current_key)
                pipe.expire(current_key, window_seconds + 5)
                results = await pipe.execute()
            
            current_count = results[0]
            if current_count > limit:
                logger.warning("Rate limit exceeded", key=key, current_count=current_count, limit=limit)
                return False
            
            return True
        except Exception as e:
            logger.error("Redis rate limiter error", error=str(e))
            return True
    
    async def acquire(self, key: str) -> Tuple[bool, Dict[str, Any]]:
        """Acquire rate limit token and return (is_allowed, info)"""
        is_allowed = await self.check_limit(key, self.max_requests, self.window_seconds)
        info = {
            "key": key,
            "limit": self.max_requests,
            "window_seconds": self.window_seconds,
            "burst_size": self.burst_size,
            "is_allowed": is_allowed
        }
        return is_allowed, info
                
    async def wait_if_needed(self, key: str, limit: int, window_seconds: int):
        is_allowed = await self.check_limit(key, limit, window_seconds)
        if not is_allowed:
            raise EnrichmentError(
                ErrorCode.RATE_LIMIT_EXCEED, 
                f"Rate limit reached for source {key}. Please try again later."
            )
        