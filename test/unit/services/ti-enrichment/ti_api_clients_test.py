import asyncio
from unittest.mock import AsyncMock

from services.abuseipdb import AbuseIPDBClient
from services.hybrid_analysis import HybridAnalysisClient
from services.otx import OTXClient
from services.virustotal import VirusTotalClient


def test_abuseipdb_get_ip_report_calls_expected_endpoint_and_params():
    client = AbuseIPDBClient(api_key="api-key")
    client._request = AsyncMock(return_value={"data": {"abuseConfidenceScore": 42}})

    result = asyncio.run(client.get_ip_report("1.1.1.1"))

    client._request.assert_awaited_once_with(
        "GET",
        "check",
        params={
            "ipAddress": "1.1.1.1",
            "maxAgeInDays": 90,
            "verbose": "",
        },
    )
    assert result["provider"] == "abuseipdb"
    assert result["ip"] == "1.1.1.1"


def test_hybrid_analysis_report_methods_call_expected_endpoints_and_query_param():
    client = HybridAnalysisClient(api_key="api-key")

    cases = [
        (client.get_ip_report, "8.8.8.8", "search/ip"),
        (client.get_domain_report, "example.com", "search/domain"),
        (client.get_hash_report, "a" * 64, "search/hash"),
        (client.get_url_report, "https://evil.example", "search/url"),
    ]

    for method, ioc_value, endpoint in cases:
        client._request = AsyncMock(return_value=[])

        asyncio.run(method(ioc_value))

        client._request.assert_awaited_once_with(
            "GET",
            endpoint,
            params={"query": ioc_value},
        )


def test_otx_report_methods_call_expected_endpoints():
    client = OTXClient(api_key="api-key")

    client._request = AsyncMock(return_value={})
    asyncio.run(client.get_ip_report("8.8.8.8"))
    client._request.assert_awaited_once_with("GET", "indicators/IPv4/8.8.8.8/general")

    client._request = AsyncMock(return_value={})
    asyncio.run(client.get_domain_report("example.com"))
    client._request.assert_awaited_once_with("GET", "indicators/domain/example.com/general")

    test_hash = "a" * 64
    client._request = AsyncMock(return_value={})
    asyncio.run(client.get_hash_report(test_hash))
    client._request.assert_awaited_once_with("GET", f"indicators/file/{test_hash}/general")


def test_virustotal_report_methods_call_expected_endpoints():
    client = VirusTotalClient(api_key="api-key")

    cases = [
        (client.get_ip_report, "8.8.4.4", "ip_addresses/8.8.4.4"),
        (client.get_domain_report, "example.org", "domains/example.org"),
        (client.get_hash_report, "b" * 64, f"files/{'b' * 64}"),
        (client.get_url_report, "https://phish.example", "urls/https://phish.example"),
    ]

    for method, ioc_value, endpoint in cases:
        client._request = AsyncMock(return_value={})

        asyncio.run(method(ioc_value))

        client._request.assert_awaited_once_with("GET", endpoint)
