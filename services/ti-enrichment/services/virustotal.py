from typing import Any, Dict, Optional
from clients.base import BaseTIClient
from utils.errors import EnrichmentError, ErrorCode
from domain.models import EnrichmentSource


class VirusTotalClient(BaseTIClient):
    """VirusTotal API v3 client for threat intelligence"""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://www.virustotal.com/api/v3",
        timeout: int = 15,
    ):
        super().__init__(base_url, api_key, timeout)

    def _get_default_headers(self) -> Dict[str, str]:
        return {
            "x-api-key": self.api_key,
            "Accept": "application/json"
        }

    async def get_ip_report(self, ip: str) -> Dict[str, Any]:
        """Get VirusTotal report for an IP address"""
        try:
            response = await self._request("GET", f"ip_addresses/{ip}")
            return self._parse_ip_response(response, ip)
        except Exception as e:
            self.logger.error("Failed to get VirusTotal report", ioc_type="ip", ioc_value=ip, error=str(e))
            raise

    async def get_domain_report(self, domain: str) -> Dict[str, Any]:
        """Get VirusTotal report for a domain"""
        try:
            response = await self._request("GET", f"domains/{domain}")
            return self._parse_domain_response(response, domain)
        except Exception as e:
            self.logger.error("Failed to get VirusTotal report", ioc_type="domain", ioc_value=domain, error=str(e))
            raise

    async def get_hash_report(self, hash_value: str) -> Dict[str, Any]:
        """Get VirusTotal report for a file hash"""
        try:
            response = await self._request("GET", f"files/{hash_value}")
            return self._parse_hash_response(response, hash_value)
        except Exception as e:
            self.logger.error("Failed to get VirusTotal report", ioc_type="hash", ioc_value=hash_value, error=str(e))
            raise

    async def get_url_report(self, url: str) -> Dict[str, Any]:
        """Get VirusTotal report for a URL"""
        try:
            response = await self._request("GET", f"urls/{url}")
            return self._parse_url_response(response, url)
        except Exception as e:
            self.logger.error("Failed to get VirusTotal report", ioc_type="url", ioc_value=url, error=str(e))
            raise

    async def get_file_path_report(self, file_path: str) -> Dict[str, Any]:
        """VirusTotal does not support file path enrichment"""
        raise EnrichmentError(
            ErrorCode.NOT_IMPLEMENTED,
            "VirusTotal does not support file path enrichment",
            source=self.name
        )

    async def get_source_health(self) -> bool:
        """Check if VirusTotal API is healthy"""
        try:
            await self._request("GET", "domains/google.com")
            return True
        except Exception as e:
            self.logger.warning("VirusTotal health check failed", error=str(e))
            return False

    def _parse_ip_response(self, response: Dict[str, Any], ip: str) -> Dict[str, Any]:
        """Parse VirusTotal IP response"""
        if not response or "data" not in response:
            return {
                "provider": EnrichmentSource.VIRUSTOTAL.value,
                "ip": ip,
                "error": "Empty or invalid response from VirusTotal"
            }

        data = response.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        total_votes = attributes.get("total_votes", {})
        
        return {
            "provider": EnrichmentSource.VIRUSTOTAL.value,
            "ip": ip,
            "type": data.get("type", "ip_address"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
            "reputation": attributes.get("reputation", 0),
            "asn": attributes.get("asn"),
            "country": attributes.get("country"),
            "tags": attributes.get("tags", []),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "last_modification_date": attributes.get("last_modification_date"),
            "total_votes": {
                "malicious": total_votes.get("malicious", 0),
                "harmless": total_votes.get("harmless", 0)
            },
            "link": data.get("links", {}).get("self"),
            "crowdsourced_context": self._extract_crowdsourced_context(attributes.get("crowdsourced_context", []))
        }

    def _parse_domain_response(self, response: Dict[str, Any], domain: str) -> Dict[str, Any]:
        """Parse VirusTotal domain response"""
        if not response or "data" not in response:
            return {
                "provider": EnrichmentSource.VIRUSTOTAL.value,
                "domain": domain,
                "error": "Empty or invalid response from VirusTotal"
            }

        data = response.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        total_votes = attributes.get("total_votes", {})

        return {
            "provider": EnrichmentSource.VIRUSTOTAL.value,
            "domain": domain,
            "type": data.get("type", "domain"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
            "reputation": attributes.get("reputation", 0),
            "tags": attributes.get("tags", []),
            "categories": attributes.get("categories", {}),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "last_modification_date": attributes.get("last_modification_date"),
            "total_votes": {
                "malicious": total_votes.get("malicious", 0),
                "harmless": total_votes.get("harmless", 0)
            },
            "tld": attributes.get("tld"),
            "registrar": attributes.get("registrar"),
            "last_dns_records": attributes.get("last_dns_records", [])[:5],  # Limit to first 5
            "link": data.get("links", {}).get("self"),
            "crowdsourced_context": self._extract_crowdsourced_context(attributes.get("crowdsourced_context", []))
        }

    def _parse_hash_response(self, response: Dict[str, Any], hash_value: str) -> Dict[str, Any]:
        """Parse VirusTotal file hash response"""
        if not response or "data" not in response:
            return {
                "provider": EnrichmentSource.VIRUSTOTAL.value,
                "hash": hash_value,
                "error": "Empty or invalid response from VirusTotal"
            }

        data = response.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        total_votes = attributes.get("total_votes", {})

        return {
            "provider": EnrichmentSource.VIRUSTOTAL.value,
            "hash": hash_value,
            "type": data.get("type", "file"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
            "reputation": attributes.get("reputation", 0),
            "tags": attributes.get("tags", []),
            "size": attributes.get("size"),
            "type_description": attributes.get("type_description"),
            "meaningful_name": attributes.get("meaningful_name") or attributes.get("title"),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "last_modification_date": attributes.get("last_modification_date"),
            "total_votes": {
                "malicious": total_votes.get("malicious", 0),
                "harmless": total_votes.get("harmless", 0)
            },
            "magic": attributes.get("magic"),
            "sha256": attributes.get("sha256"),
            "sha1": attributes.get("sha1"),
            "md5": attributes.get("md5"),
            "link": data.get("links", {}).get("self"),
            "crowdsourced_context": self._extract_crowdsourced_context(attributes.get("crowdsourced_context", []))
        }

    def _parse_url_response(self, response: Dict[str, Any], url: str) -> Dict[str, Any]:
        """Parse VirusTotal URL response"""
        if not response or "data" not in response:
            return {
                "provider": EnrichmentSource.VIRUSTOTAL.value,
                "url": url,
                "error": "Empty or invalid response from VirusTotal"
            }

        data = response.get("data", {})
        attributes = data.get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        total_votes = attributes.get("total_votes", {})

        return {
            "provider": EnrichmentSource.VIRUSTOTAL.value,
            "url": url,
            "type": data.get("type", "url"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "timeout": stats.get("timeout", 0),
            "reputation": attributes.get("reputation", 0),
            "tags": attributes.get("tags", []),
            "categories": attributes.get("categories", {}),
            "last_analysis_date": attributes.get("last_analysis_date"),
            "last_modification_date": attributes.get("last_modification_date"),
            "total_votes": {
                "malicious": total_votes.get("malicious", 0),
                "harmless": total_votes.get("harmless", 0)
            },
            "last_http_response_code": attributes.get("last_http_response_code"),
            "last_http_response_headers": attributes.get("last_http_response_headers", {}),
            "link": data.get("links", {}).get("self"),
            "crowdsourced_context": self._extract_crowdsourced_context(attributes.get("crowdsourced_context", []))
        }

    def _extract_crowdsourced_context(self, context_list: list) -> list:
        """Extract and simplify crowdsourced context information"""
        if not isinstance(context_list, list):
            return []
        
        simplified = []
        for ctx in context_list[:3]:  # Limit to first 3
            if isinstance(ctx, dict):
                simplified.append({
                    "title": ctx.get("title"),
                    "severity": ctx.get("severity"),
                    "source": ctx.get("source"),
                })
        return simplified