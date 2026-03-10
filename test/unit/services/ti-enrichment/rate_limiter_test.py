import pytest
import asyncio

from utils.errors import EnrichmentError
from utils.rate_limiter import RateLimiter


class FakePipeline:
    def __init__(self, redis):
        self.redis = redis
        self.key = None

    def incr(self, key):
        self.key = key

    def expire(self, key, _ttl):
        self.key = key

    async def execute(self):
        self.redis.counts[self.key] = self.redis.counts.get(self.key, 0) + 1
        return [self.redis.counts[self.key], True]


class FakePipelineContext:
    def __init__(self, redis):
        self.redis = redis

    async def __aenter__(self):
        return FakePipeline(self.redis)

    async def __aexit__(self, exc_type, exc, tb):
        return False


class FakeRedis:
    def __init__(self):
        self.counts = {}

    def pipeline(self, transaction=True):
        return FakePipelineContext(self)


def test_rate_limiter_allows_under_limit():
    limiter = RateLimiter(FakeRedis(), max_requests=2, window_seconds=60)

    allowed, info = asyncio.run(limiter.acquire("vt"))

    assert allowed is True
    assert info["is_allowed"] is True
    assert info["limit"] == 2


def test_rate_limiter_blocks_over_limit():
    limiter = RateLimiter(FakeRedis(), max_requests=1, window_seconds=60)

    first = asyncio.run(limiter.check_limit("otx", 1, 60))
    second = asyncio.run(limiter.check_limit("otx", 1, 60))

    assert first is True
    assert second is False


def test_wait_if_needed_raises_when_exceeded():
    limiter = RateLimiter(FakeRedis(), max_requests=1, window_seconds=60)

    asyncio.run(limiter.check_limit("abuseipdb", 1, 60))
    with pytest.raises(EnrichmentError):
        asyncio.run(limiter.wait_if_needed("abuseipdb", 1, 60))
