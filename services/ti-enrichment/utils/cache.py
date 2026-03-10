import json

from utils.logger import get_logger
from typing import Optional, Any, Dict
import redis.asyncio as redis

logger = get_logger("cache_util")

class CacheUtil:
    def __init__(self, redis_client: redis.Redis, key_prefix: str = "enrichment:", ttl: int = 86400):
        self.redis = redis_client
        self.key_prefix = key_prefix
        self.ttl = ttl
    
    def _get_key(self, key: str) -> str:
        return f"{self.key_prefix}{key}"
    
    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        full_key = self._get_key(key)
        try:
            cached_value = await self.redis.get(full_key)
            if not cached_value:
                return None
            
            return json.loads(cached_value)
        except json.JSONDecodeError as e:
            logger.error("Cache data corruption", key=full_key, error=str(e))
            return None
        except Exception as e:
            logger.error("Redis connection error", error=str(e))
            return None
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        full_key = self._get_key(key)
        try:
            ttl_to_use = ttl if ttl is not None else self.ttl
            json_value = json.dumps(value) if not isinstance(value, str) else value
            await self.redis.set(full_key, json_value, ex=ttl_to_use)
            return True
        except Exception as e:
            logger.error("Failed to cache data", key=full_key, error=str(e))
            return False
    
    async def delete(self, key: str) -> bool:
        try:
            await self.redis.delete(self._get_key(key))
            return True
        except Exception as e:
            logger.error("Failed to delete cache key", key=key, error=str(e))
            return False
        
    async def exists(self, key: str) -> bool:
        try:
            return await self.redis.exists(self._get_key(key)) > 0
        except Exception as e:
            logger.error("Failed to check cache existence", error=str(e))
            return False