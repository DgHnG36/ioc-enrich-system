from typing import Any, Dict, Optional
from clients.base import BaseTIClient
from utils.errors import EnrichmentError, ErrorCode


class HybridAnalysisClient(BaseTIClient):
    """Hybrid Analysis API client for malware and file analysis"""

    def __init__(
        self,
        api_key: str,
        base_url: str = "https://www.hybrid-analysis.com/api/v2",
        timeout: int = 15,
    ):
        super().__init__(base_url, api_key, timeout)

    def _get_default_headers(self) -> Dict[str, str]:
        return {
            "api-key": self.api_key,
            "Accept": "application/json",
            "User-Agent": "ioc-enrichment-service/1.0"
        }

    async def get_ip_report(self, ip: str) -> Dict[str, Any]:
        """Get threat intelligence for an IP address"""
        try:
            response = await self._request("GET", f"search/ip", params={"query": ip})
            return self._parse_ip_response(response, ip)
        except Exception as e:
            self.logger.error("Failed to get Hybrid Analysis report", ioc_type="ip", ioc_value=ip, error=str(e))
            raise

    async def get_domain_report(self, domain: str) -> Dict[str, Any]:
        """Get threat intelligence for a domain"""
        try:
            response = await self._request(
                "GET",
                "search/domain",
                params={"query": domain}
            )
            return self._parse_domain_response(response, domain)
        except Exception as e:
            self.logger.error("Failed to get Hybrid Analysis domain report", ioc_type="domain", ioc_value=domain, error=str(e))
            raise

    async def get_hash_report(self, hash_value: str) -> Dict[str, Any]:
        """Get threat intelligence for a file hash"""
        try:
            response = await self._request(
                "GET",
                "search/hash",
                params={"query": hash_value}
            )
            return self._parse_hash_response(response, hash_value)
        except Exception as e:
            self.logger.error("Failed to get Hybrid Analysis hash report", ioc_type="hash", ioc_value=hash_value, error=str(e))
            raise

    async def get_url_report(self, url: str) -> Dict[str, Any]:
        """Get threat intelligence for a URL"""
        try:
            response = await self._request(
                "GET",
                "search/url",
                params={"query": url}
            )
            return self._parse_url_response(response, url)
        except Exception as e:
            self.logger.error("Failed to get Hybrid Analysis URL report", ioc_type="url", ioc_value=url, error=str(e))
            raise

    async def get_file_path_report(self, file_path: str) -> Dict[str, Any]:
        """Hybrid Analysis does not support file path enrichment"""
        raise EnrichmentError(
            ErrorCode.NOT_IMPLEMENTED,
            "Hybrid Analysis does not support file path enrichment",
            source=self.name
        )

    async def get_source_health(self) -> bool:
        """Check if Hybrid Analysis API is healthy"""
        try:
            # Hybrid Analysis doesn't have a direct health endpoint
            # We'll check by attempting a minimal request
            await self._request("GET", "stats")
            return True
        except Exception as e:
            self.logger.warning("Hybrid Analysis health check failed", error=str(e))
            return False

    def _parse_ip_response(self, response: Dict[str, Any], ip: str) -> Dict[str, Any]:
        """Parse Hybrid Analysis IP response"""
        if isinstance(response, dict) and "response_code" in response:
            response_data = response.get("response", [])
        else:
            response_data = response if isinstance(response, list) else []

        submissions = response_data if isinstance(response_data, list) else []

        return {
            "provider": "hybrid_analysis",
            "ip": ip,
            "submissions_count": len(submissions),
            "submissions": [{
                "sha256": s.get("sha256"),
                "verdict": s.get("verdict"),
                "threat_level": s.get("threat_level"),
                "threat_score": s.get("threat_score"),
                "analysis_date": s.get("analysis_date"),
                "tags": s.get("tags", []),
            } for s in submissions[:5]],  # Limit to first 5
        }

    def _parse_domain_response(self, response: Dict[str, Any], domain: str) -> Dict[str, Any]:
        """Parse Hybrid Analysis domain response"""
        if isinstance(response, dict) and "response_code" in response:
            response_data = response.get("response", [])
        else:
            response_data = response if isinstance(response, list) else []

        submissions = response_data if isinstance(response_data, list) else []

        return {
            "provider": "hybrid_analysis",
            "domain": domain,
            "submissions_count": len(submissions),
            "submissions": [{
                "sha256": s.get("sha256"),
                "verdict": s.get("verdict"),
                "threat_level": s.get("threat_level"),
                "threat_score": s.get("threat_score"),
                "submission_date": s.get("submission_date"),
            } for s in submissions[:5]],
        }

    def _parse_hash_response(self, response: Dict[str, Any], hash_value: str) -> Dict[str, Any]:
        """Parse Hybrid Analysis hash response"""
        if isinstance(response, dict) and "response_code" in response:
            analysis = response.get("response", {})
        else:
            analysis = response if isinstance(response, dict) else {}

        return {
            "provider": "hybrid_analysis",
            "hash": hash_value,
            "verdict": analysis.get("verdict"),
            "threat_level": analysis.get("threat_level"),
            "threat_score": analysis.get("threat_score"),
            "verdict_reason": analysis.get("verdict_reason"),
            "av_detect": analysis.get("av_detect"),
            "vx_family": analysis.get("vx_family"),
            "file_type": analysis.get("file_type"),
            "file_size": analysis.get("file_size"),
            "ssdeep": analysis.get("ssdeep"),
            "imphash": analysis.get("imphash"),
            "submission_date": analysis.get("submission_date"),
            "last_analysis_date": analysis.get("last_analysis_date"),
            "tags": analysis.get("tags", []),
        }

    def _parse_url_response(self, response: Dict[str, Any], url: str) -> Dict[str, Any]:
        """Parse Hybrid Analysis URL response"""
        if isinstance(response, dict) and "response_code" in response:
            response_data = response.get("response", [])
        else:
            response_data = response if isinstance(response, list) else []

        submissions = response_data if isinstance(response_data, list) else []

        return {
            "provider": "hybrid_analysis",
            "url": url,
            "submissions_count": len(submissions),
            "submissions": [{
                "sha256": s.get("sha256"),
                "verdict": s.get("verdict"),
                "threat_level": s.get("threat_level"),
                "threat_score": s.get("threat_score"),
                "submission_date": s.get("submission_date"),
            } for s in submissions[:5]],
        }
