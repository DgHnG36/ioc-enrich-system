import asyncio

import pytest

from clients.base import BaseTIClient
from utils.errors import EnrichmentError, ErrorCode


class DummyClient(BaseTIClient):
    async def get_ip_report(self, ip: str):
        return {"ip": ip, "ok": True}


class FakeSession:
    def __init__(self):
        self.closed = False

    async def close(self):
        self.closed = True


def test_get_report_dispatch_success():
    client = DummyClient("https://example.com", "k")
    result = asyncio.run(client.get_report("1.1.1.1", "ip"))
    assert result["ok"] is True
    assert result["ip"] == "1.1.1.1"


def test_get_report_not_implemented_raises():
    client = DummyClient("https://example.com", "k")

    with pytest.raises(EnrichmentError) as exc:
        asyncio.run(client.get_report("abc", "domain"))

    assert exc.value.code == ErrorCode.NOT_IMPLEMENTED


def test_get_batch_report_mixed_results():
    class MixedClient(DummyClient):
        async def get_domain_report(self, domain: str):
            raise RuntimeError("domain failed")

    client = MixedClient("https://example.com", "k")
    batch = {"1.1.1.1": "ip", "example.com": "domain"}

    result = asyncio.run(client.get_batch_report(batch))

    assert "1.1.1.1" in result
    assert result["1.1.1.1"]["ok"] is True
    assert "error" in result["example.com"]


def test_get_source_health_true_on_session():
    client = DummyClient("https://example.com", "k")

    async def fake_get_session():
        return FakeSession()

    client._get_session = fake_get_session  # type: ignore[attr-defined]
    ok = asyncio.run(client.get_source_health())

    assert ok is True


def test_close_closes_session():
    client = DummyClient("https://example.com", "k")
    client._session = FakeSession()  # type: ignore[attr-defined]

    asyncio.run(client.close())
    assert client._session.closed is True
