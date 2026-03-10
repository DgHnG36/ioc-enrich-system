import pytest
import asyncio

from utils.retry import RetryError, retry, retry_async


def test_retry_sync_success_after_failures():
    state = {"calls": 0}

    @retry(max_attempts=3, base_delay=0, max_delay=0, use_jitter=False)
    def flaky():
        state["calls"] += 1
        if state["calls"] < 2:
            raise ValueError("temporary")
        return "ok"

    assert flaky() == "ok"
    assert state["calls"] == 2


def test_retry_sync_raises_retry_error():
    @retry(max_attempts=2, base_delay=0, max_delay=0, use_jitter=False)
    def always_fail():
        raise RuntimeError("boom")

    with pytest.raises(RetryError):
        always_fail()


def test_retry_async_helper_success_after_retry():
    state = {"calls": 0}

    async def flaky_async():
        state["calls"] += 1
        if state["calls"] < 2:
            raise ValueError("temporary")
        return "ok"

    result = asyncio.run(retry_async(flaky_async, max_attempts=2))
    assert result == "ok"
    assert state["calls"] == 2


def test_retry_decorator_async_success():
    state = {"calls": 0}

    @retry(max_attempts=3, base_delay=0, max_delay=0, use_jitter=False)
    async def flaky_async():
        state["calls"] += 1
        if state["calls"] < 3:
            raise RuntimeError("retry")
        return 123

    assert asyncio.run(flaky_async()) == 123
    assert state["calls"] == 3
