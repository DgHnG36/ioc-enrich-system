import json
import asyncio

import pytest

from utils.cache import CacheUtil


class FakeRedis:
    def __init__(self):
        self.store = {}

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex=None):
        self.store[key] = value
        return True

    async def delete(self, key):
        self.store.pop(key, None)
        return 1

    async def exists(self, key):
        return 1 if key in self.store else 0


class BrokenRedis(FakeRedis):
    async def get(self, key):
        raise RuntimeError("redis down")


def test_cache_set_and_get_json_value():
    redis = FakeRedis()
    cache = CacheUtil(redis, key_prefix="test:")

    ok = asyncio.run(cache.set("k1", {"a": 1}))
    value = asyncio.run(cache.get("k1"))

    assert ok is True
    assert value == {"a": 1}


def test_cache_get_returns_none_for_invalid_json():
    redis = FakeRedis()
    cache = CacheUtil(redis, key_prefix="test:")
    redis.store["test:bad"] = "{not-json"

    value = asyncio.run(cache.get("bad"))

    assert value is None


def test_cache_exists_and_delete():
    redis = FakeRedis()
    cache = CacheUtil(redis, key_prefix="test:")

    asyncio.run(cache.set("k2", json.dumps({"v": 2})))
    assert asyncio.run(cache.exists("k2")) is True

    assert asyncio.run(cache.delete("k2")) is True
    assert asyncio.run(cache.exists("k2")) is False


def test_cache_redis_error_returns_none():
    cache = CacheUtil(BrokenRedis(), key_prefix="test:")
    value = asyncio.run(cache.get("k"))
    assert value is None
