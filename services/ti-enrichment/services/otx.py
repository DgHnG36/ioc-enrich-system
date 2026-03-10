from typing import Any, Dict, Optional
from clients.base import BaseTIClient
from utils.errors import EnrichmentError, ErrorCode


class OTXClient(BaseTIClient):
    """AlienVault OTX (Open Threat Exchange) API client"""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://otx.alienvault.com/api/v1",
        timeout: int = 15,
    ):
        super().__init__(base_url, api_key, timeout)

    def _get_default_headers(self) -> Dict[str, str]:
        return {
            "X-OTX-API-KEY": self.api_key,
            "Accept": "application/json",
        }

    async def get_ip_report(self, ip: str) -> Dict[str, Any]:
        """Get threat intelligence for an IP address from OTX"""
        try:
            response = await self._request("GET", f"indicators/IPv4/{ip}/general")
            return self._parse_ip_response(response, ip)
        except Exception as e:
            self.logger.error("Failed to get OTX report", ioc_type="ip", ioc_value=ip, error=str(e))
            raise

    async def get_domain_report(self, domain: str) -> Dict[str, Any]:
        """Get threat intelligence for a domain from OTX"""
        try:
            response = await self._request("GET", f"indicators/domain/{domain}/general")
            return self._parse_domain_response(response, domain)
        except Exception as e:
            self.logger.error("Failed to get OTX domain report", ioc_type="domain", ioc_value=domain, error=str(e))
            raise

    async def get_hash_report(self, hash_value: str) -> Dict[str, Any]:
        """Get threat intelligence for a file hash from OTX"""
        try:
            # Detect hash type (MD5, SHA1, SHA256)
            hash_type = self._detect_hash_type(hash_value)
            response = await self._request("GET", f"indicators/file/{hash_value}/general")
            return self._parse_hash_response(response, hash_value, hash_type)
        except Exception as e:
            self.logger.error("Failed to get OTX hash report", ioc_type="hash", ioc_value=hash_value, error=str(e))
            raise

    async def get_url_report(self, url: str) -> Dict[str, Any]:
        """OTX does not directly support URL enrichment via this endpoint"""
        raise EnrichmentError(
            ErrorCode.NOT_IMPLEMENTED,
            "OTX does not support direct URL enrichment",
            source=self.name
        )

    async def get_file_path_report(self, file_path: str) -> Dict[str, Any]:
        """OTX does not support file path enrichment"""
        raise EnrichmentError(
            ErrorCode.NOT_IMPLEMENTED,
            "OTX does not support file path enrichment",
            source=self.name
        )

    async def get_source_health(self) -> bool:
        """Check if OTX API is healthy"""
        try:
            await self.get_ip_report("8.8.8.8")
            return True
        except Exception as e:
            self.logger.warning("OTX health check failed", error=str(e))
            return False

    def _detect_hash_type(self, hash_value: str) -> str:
        """Detect hash type based on length"""
        hash_len = len(hash_value)
        if hash_len == 32:
            return "MD5"
        elif hash_len == 40:
            return "SHA1"
        elif hash_len == 64:
            return "SHA256"
        else:
            return "UNKNOWN"

    def _parse_ip_response(self, response: Dict[str, Any], ip: str) -> Dict[str, Any]:
        """Parse OTX IP response"""
        if not response:
            return {
                "provider": "otx",
                "indicator": ip,
                "type": "IPv4",
                "error": "Empty response"
            }

        pulses = response.get("pulse_info", {}).get("pulses", [])
        validation = response.get("validation", [])
        false_positives = response.get("false_positive", [])

        return {
            "provider": "otx",
            "indicator": ip,
            "type": response.get("type", "IPv4"),
            "reputation": response.get("reputation", 0),
            "whois": response.get("whois", ""),
            "asn": response.get("asn", ""),
            "country_code": response.get("country_code", ""),
            "city": response.get("city"),
            "latitude": response.get("latitude"),
            "longitude": response.get("longitude"),
            "continent_code": response.get("continent_code", ""),
            "pulse_count": len(pulses),
            "pulses": [{
                "id": p.get("id"),
                "name": p.get("name"),
                "description": p.get("description", ""),
                "created": p.get("created"),
                "modified": p.get("modified"),
                "targeted_countries": p.get("targeted_countries", []),
                "malware_families": p.get("malware_families", []),
                "adversaries": p.get("adversary", []),
            } for p in pulses[:5]],  # Limit to first 5 pulses
            "validation": validation,
            "false_positive_count": len(false_positives),
            "tags": response.get("base_indicator", {}).get("title", ""),
        }

    def _parse_domain_response(self, response: Dict[str, Any], domain: str) -> Dict[str, Any]:
        """Parse OTX domain response"""
        if not response:
            return {
                "provider": "otx",
                "indicator": domain,
                "type": "domain",
                "error": "Empty response"
            }

        pulses = response.get("pulse_info", {}).get("pulses", [])

        return {
            "provider": "otx",
            "indicator": domain,
            "type": "domain",
            "reputation": response.get("reputation", 0),
            "whois": response.get("whois", ""),
            "alexa_rank": response.get("alexa_rank"),
            "pulse_count": len(pulses),
            "pulses": [{
                "id": p.get("id"),
                "name": p.get("name"),
                "description": p.get("description", ""),
                "created": p.get("created"),
                "targeted_countries": p.get("targeted_countries", []),
            } for p in pulses[:5]],
        }

    def _parse_hash_response(self, response: Dict[str, Any], hash_value: str, hash_type: str) -> Dict[str, Any]:
        """Parse OTX hash response"""
        if not response:
            return {
                "provider": "otx",
                "indicator": hash_value,
                "type": hash_type,
                "error": "Empty response"
            }

        pulses = response.get("pulse_info", {}).get("pulses", [])

        return {
            "provider": "otx",
            "indicator": hash_value,
            "type": hash_type,
            "reputation": response.get("reputation", 0),
            "file_class": response.get("file_class"),
            "file_type": response.get("file_type"),
            "pulse_count": len(pulses),
            "pulses": [{
                "id": p.get("id"),
                "name": p.get("name"),
                "description": p.get("description", ""),
                "malware_families": p.get("malware_families", []),
            } for p in pulses[:5]],
        }
