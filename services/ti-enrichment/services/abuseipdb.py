from typing import Any, Dict, Optional
from clients.base import BaseTIClient
from utils.errors import EnrichmentError, ErrorCode


class AbuseIPDBClient(BaseTIClient):
    """AbuseIPDB API client for IP reputation enrichment"""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://api.abuseipdb.com/api/v2",
        timeout: int = 15,
    ):
        super().__init__(base_url, api_key, timeout)

    def _get_default_headers(self) -> Dict[str, str]:
        return {
            "Key": self.api_key,
            "Accept": "application/json",
        }

    async def get_ip_report(self, ip: str) -> Dict[str, Any]:
        """Get abuse report for an IP address"""
        try:
            response = await self._request(
                "GET",
                "check",
                params={
                    "ipAddress": ip,
                    "maxAgeInDays": 90,
                    "verbose": "",
                }
            )
            return self._parse_response(response, ip)
        except Exception as e:
            self.logger.error("Failed to get AbuseIPDB report", ip=ip, error=str(e))
            raise

    async def get_domain_report(self, domain: str) -> Dict[str, Any]:
        """AbuseIPDB does not support domain enrichment"""
        raise EnrichmentError(
            ErrorCode.NOT_IMPLEMENTED,
            "AbuseIPDB does not support domain enrichment",
            source=self.name
        )

    async def get_hash_report(self, hash_value: str) -> Dict[str, Any]:
        """AbuseIPDB does not support hash enrichment"""
        raise EnrichmentError(
            ErrorCode.NOT_IMPLEMENTED,
            "AbuseIPDB does not support hash enrichment",
            source=self.name
        )

    async def get_url_report(self, url: str) -> Dict[str, Any]:
        """AbuseIPDB does not support URL enrichment"""
        raise EnrichmentError(
            ErrorCode.NOT_IMPLEMENTED,
            "AbuseIPDB does not support URL enrichment",
            source=self.name
        )

    async def get_file_path_report(self, file_path: str) -> Dict[str, Any]:
        """AbuseIPDB does not support file path enrichment"""
        raise EnrichmentError(
            ErrorCode.NOT_IMPLEMENTED,
            "AbuseIPDB does not support file path enrichment",
            source=self.name
        )

    async def get_source_health(self) -> bool:
        """Check if AbuseIPDB API is healthy"""
        try:
            # Try to check a safe IP
            await self.get_ip_report("8.8.8.8")
            return True
        except Exception as e:
            self.logger.warning("AbuseIPDB health check failed", error=str(e))
            return False

    def _parse_response(self, response: Dict[str, Any], ip: str) -> Dict[str, Any]:
        """Parse AbuseIPDB API response"""
        if not response or "data" not in response:
            return {
                "provider": "abuseipdb",
                "ip": ip,
                "error": "Empty or invalid response"
            }

        data = response.get("data", {})

        return {
            "provider": "abuseipdb",
            "ip": ip,
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "is_public": data.get("isPublic", False),
            "is_whitelisted": data.get("isWhitelisted", False),
            "is_tor": data.get("isTor", False),
            "is_proxy": data.get("isProxy", False),
            "is_vpn": data.get("isVpn", False),
            "country_code": data.get("countryCode", ""),
            "country_name": data.get("countryName", ""),
            "usage_type": data.get("usageType", ""),
            "isp": data.get("isp", ""),
            "domain": data.get("domain", ""),
            "hostnames": data.get("hostnames", []),
            "total_reports": data.get("totalReports", 0),
            "num_distinct_users": data.get("numDistinctUsers", 0),
            "last_reported_at": data.get("lastReportedAt"),
            "reports": data.get("reports", []),
        }
