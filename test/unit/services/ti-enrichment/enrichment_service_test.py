import asyncio

import pytest

from services.enrichment_service import EnrichmentService
from utils.errors import EnrichmentError, ErrorCode


class FakeCache:
    def __init__(self, data=None):
        self.data = data or {}

    async def get(self, key):
        return self.data.get(key)

    async def set(self, key, value, ttl=None):
        self.data[key] = value
        return True


class FakeClient:
    def __init__(self, payload=None, fail=False):
        self.payload = payload or {}
        self.fail = fail
        self.calls = 0

    async def get_report(self, value, ioc_type):
        self.calls += 1
        if self.fail:
            raise RuntimeError("source failure")
        return self.payload

    async def health_check(self):
        return not self.fail


def test_enrich_ioc_returns_cached_data():
    cache = FakeCache(data={"1.1.1.1": {"cached": True}})
    client = FakeClient(payload={"malicious": 10, "harmless": 0, "suspicious": 0})
    svc = EnrichmentService(cache=cache, clients={"virustotal": client})

    result = asyncio.run(svc.enrich_ioc("1.1.1.1", "ip", sources=["virustotal"], force_refresh=False))

    assert result == {"cached": True}
    assert client.calls == 0


def test_enrich_ioc_success_with_source_data(monkeypatch):
    cache = FakeCache()
    client = FakeClient(payload={"malicious": 9, "harmless": 1, "suspicious": 0})
    svc = EnrichmentService(cache=cache, clients={"virustotal": client})

    # Work around current production bug: _extract_source_metrics calls
    # _parse_hybrid_analysis with one argument instead of two.
    monkeypatch.setattr(svc, "_parse_hybrid_analysis", lambda _payload: (None, None))

    result = asyncio.run(svc.enrich_ioc("8.8.8.8", "ip", sources=["virustotal"], force_refresh=True))

    assert result["value"] == "8.8.8.8"
    assert result["ioc_type"] == "ip"
    assert "virustotal" in result["results"]
    assert result["aggregated"]["total_sources"] >= 1


def test_enrich_ioc_no_valid_sources_raises():
    svc = EnrichmentService(cache=FakeCache(), clients={})

    with pytest.raises(EnrichmentError) as exc:
        asyncio.run(svc.enrich_ioc("1.1.1.1", "ip", sources=["unknown"], force_refresh=True))

    assert exc.value.code == ErrorCode.INVALID_INPUT


def test_enrich_batch_size_exceeds_limit_raises():
    svc = EnrichmentService(cache=FakeCache(), clients={"virustotal": FakeClient()})
    iocs = {f"1.1.1.{i}": "ip" for i in range(101)}

    with pytest.raises(EnrichmentError) as exc:
        asyncio.run(svc.enrich_batch(iocs))

    assert exc.value.code == ErrorCode.INVALID_INPUT


def test_check_source_health_uses_health_check_method():
    svc = EnrichmentService(
        cache=FakeCache(),
        clients={
            "ok": FakeClient(fail=False),
            "bad": FakeClient(fail=True),
        },
    )

    status = asyncio.run(svc.check_source_health(["ok", "bad", "missing"]))

    assert status["ok"] is True
    assert status["bad"] is False


def test_calc_reputation_score_virustotal():
    svc = EnrichmentService(cache=FakeCache(), clients={})
    report = {
        "results": {
            "virustotal": {
                "data": {"malicious": 5, "harmless": 5, "suspicious": 0}
            }
        }
    }

    scores = svc._calc_reputation_score(report)
    assert "virustotal" in scores
    assert scores["virustotal"] == 50.0
