import asyncio
import time
from typing import AsyncGenerator, List, Dict, Any, Optional, Tuple
import json

from utils.logger import get_logger
from utils.cache import CacheUtil
from utils.errors import EnrichmentError, ErrorCode
from utils.validators import validate_ioc
from clients.base import BaseTIClient
from domain.models import Verdict, EnrichmentSource


class EnrichmentService:
    """Service for enriching IoCs with threat intelligence from multiple sources"""
    
    MAX_BATCH_SIZE = 100  # Maximum IoCs per batch request
    
    def __init__(
        self,
        cache: CacheUtil,
        clients: Dict[str, BaseTIClient],
    ):
        self.cache = cache
        self.clients = clients
        self.logger = get_logger("enrichment-service")

    async def enrich_ioc(
        self,
        value: str,
        ioc_type: str,
        sources: Optional[List[str]] = None,
        force_refresh: bool = False
    ) -> Dict[str, Any]:
        """
        Enrich a single IoC with threat intelligence from multiple sources
        
        Args:
            value: The IoC value to enrich
            ioc_type: Type of IoC (ip, domain, hash, url, file_path)
            sources: List of sources to query (default: all enabled sources)
            force_refresh: Force refresh even if cached
            
        Returns:
            Enrichment response with aggregated data
            
        Raises:
            EnrichmentError: If validation fails or enrichment fails
        """
        start_time = time.time()
        
        # Validate input
        try:
            validate_ioc(value, ioc_type)
        except EnrichmentError as e:
            self.logger.error("IoC validation failed",
                            value=value,
                            ioc_type=ioc_type,
                            error=str(e))
            raise
        
        self.logger.info("Enriching IoC",
                        ioc_value=value,
                        ioc_type=ioc_type,
                        sources=sources)

        # Try to get from cache first
        if not force_refresh:
            cached_data = await self.cache.get(value)
            if cached_data:
                self.logger.info(
                    "Cache hit",
                    value=value,
                    type=ioc_type
                )
                return json.loads(cached_data) if isinstance(cached_data, str) else cached_data

        # Determine which sources to use
        source_list = sources or list(self.clients.keys())
        
        if not source_list:
            raise EnrichmentError(
                ErrorCode.INVALID_INPUT,
                "No sources provided or configured for enrichment",
            )

        # Fetch data from all sources concurrently
        tasks = []
        source_names = []
        
        for source_name in source_list:
            client = self.clients.get(source_name.lower())
            if client:
                source_names.append(source_name)
                tasks.append(self._fetch_from_source(source_name, client.get_report(value, ioc_type)))
            else:
                self.logger.warning("Source not configured", source=source_name)

        if not tasks:
            raise EnrichmentError(
                ErrorCode.INVALID_INPUT,
                f"No valid sources found for: {source_list}",
            )

        # Gather results from all sources
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Aggregate results
        final_reports = {}
        for source_name, result in zip(source_names, results):
            if isinstance(result, Exception):
                self.logger.error(
                    f"Error from source {source_name}",
                    error=str(result),
                    source=source_name
                )
                final_reports[source_name] = {"error": str(result)}
            else:
                final_reports[source_name] = result

        # Calculate aggregated score
        aggregated = self._calc_aggregated_score(final_reports)

        response = {
            "value": value,
            "ioc_type": ioc_type,
            "results": final_reports,
            "aggregated": aggregated,
            "enriched_at": time.time(),
            "duration_ms": round((time.time() - start_time) * 1000, 2)
        }

        return response

    async def enrich_batch(
        self,
        iocs: Dict[str, str],
        sources: Optional[List[str]] = None,
        force_refresh: bool = False
    ) -> Dict[str, Any]:
        """
        Enrich multiple IoCs in batch
        
        Args:
            iocs: Dictionary mapping IoC values to their types
            sources: List of sources to query
            force_refresh: Force refresh even if cached
            
        Returns:
            Batch enrichment response
            
        Raises:
            EnrichmentError: If batch size exceeds limit or validation fails
        """
        # Validate batch size
        if len(iocs) > self.MAX_BATCH_SIZE:
            raise EnrichmentError(
                ErrorCode.INVALID_INPUT,
                f"Batch size {len(iocs)} exceeds maximum of {self.MAX_BATCH_SIZE}"
            )
        
        start_time = time.time()
        self.logger.info("Starting batch enrichment",
                        count=len(iocs),
                        sources=sources)

        final_results = {}
        missing_iocs = {}

        # Check cache for available data
        for val, ioc_type in iocs.items():
            if not force_refresh:
                cached = await self.cache.get(val)
                if cached:
                    final_results[val] = json.loads(cached) if isinstance(cached, str) else cached
                    continue
            missing_iocs[val] = ioc_type

        # Enrich missing IoCs concurrently
        if missing_iocs:
            tasks = [
                self.enrich_ioc(val, ioc_type, sources, force_refresh=True)
                for val, ioc_type in missing_iocs.items()
            ]
            enriched = await asyncio.gather(*tasks, return_exceptions=True)

            for val, result in zip(missing_iocs.keys(), enriched):
                if isinstance(result, Exception):
                    self.logger.error(
                        f"Error enriching {val}",
                        error=str(result)
                    )
                    final_results[val] = {"error": str(result)}
                else:
                    final_results[val] = result

        return {
            "results": final_results,
            "total": len(final_results),
            "cached_count": len(final_results) - len(missing_iocs),
            "enriched_count": len(missing_iocs),
            "duration_ms": round((time.time() - start_time) * 1000, 2)
        }

    async def stream_enrich(
        self,
        iocs: List[Dict[str, str]],
        sources: Optional[List[str]] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """
        Stream enrichment results as they complete
        
        Args:
            iocs: List of dicts with 'value' and 'type' keys
            sources: List of sources to query
            
        Yields:
            Enrichment results as they complete
        """
        tasks = [
            self.enrich_ioc(ioc["value"], ioc["type"], sources)
            for ioc in iocs
        ]

        for coro in asyncio.as_completed(tasks):
            result = await coro
            yield result

    async def get_source_health(self, sources: Optional[List[str]] = None) -> Dict[str, bool]:
        """
        Check health status of all configured sources
        
        Args:
            sources: List of sources to check (default: all)
            
        Returns:
            Dictionary mapping source names to health status
        """
        source_list = sources or list(self.clients.keys())
        
        tasks = {
            source: self.clients[source].get_source_health()
            for source in source_list
            if source in self.clients
        }

        results = await asyncio.gather(
            *tasks.values(),
            return_exceptions=True
        )

        health_status = {}
        for source, is_healthy in zip(tasks.keys(), results):
            if isinstance(is_healthy, Exception):
                health_status[source] = False
                self.logger.warning(
                    f"Health check failed for {source}",
                    error=str(is_healthy)
                )
            else:
                health_status[source] = is_healthy

        return health_status

    async def _fetch_from_source(
        self,
        source_name: str,
        coro
    ) -> Dict[str, Any]:
        """Fetch data from a source with error handling"""
        try:
            result = await coro
            return {
                "source": source_name,
                "status": "success",
                "data": result
            }
        except Exception as e:
            self.logger.error(
                f"Failed to fetch from {source_name}",
                error=str(e),
                source=source_name
            )
            return {
                "source": source_name,
                "status": "error",
                "error": str(e)
            }

    def _calc_aggregated_score(self, reports: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculate aggregated threat score from multiple sources

        Args:
            reports: Dictionary of results from different sources

        Returns:
            Aggregated score information
            
        """
        counts = {
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "unknown": 0,
            "false_positive": 0,
        }
        
        total_sources = 0
        confidence_scores = []
        total_false_positives = 0
        
        for source_name, result in reports.items():
            if not isinstance(result, dict):
                continue
            
            payload = result.get("data", result)
            if not isinstance(payload, dict):
                continue
            total_sources += 1
            source_scores, source_verdict, fps = self._extract_source_metrics(source_name, payload)
            
            # Cumulative false positives across all sources
            total_false_positives += fps
            
            # Update verdict if only false positive
            if fps > 0 and source_verdict == Verdict.UNKNOWN.value:
                source_verdict = Verdict.FALSE_POSITIVE.value
            
            # Collect confidence scores for averaging
            if source_scores:
                confidence_scores.append(max(source_scores))
                
            # Update counts based on source verdict
            self._update_verdict_counts(counts, source_verdict)
            
            # Calculate final result
        final_verdict = self._determine_final_verdict(counts, total_sources)
        overall_score = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 0.0
        
        return {
            "verdict": final_verdict,
            "overall_score": round(overall_score, 2),
            "confidence": round(overall_score / 100, 2),
            "total_sources": total_sources,
            "malicious_count": counts["malicious"],
            "suspicious_count": counts["suspicious"],
            "harmless_count": counts["harmless"],
            "unknown_count": counts["unknown"],
            "false_positive_count": total_false_positives,
        }
    
    def _extract_source_metrics(self, source_name: str, payload: Dict[str, Any]) -> Tuple[List[float], str, int]:
        candidates = []
        verdict = Verdict.UNKNOWN.value
        false_positives = 0
        
        # Parse VirusTotal results
        vt_score, vt_verdict = self._parse_virustotal(payload)
        if vt_score is not None:
            candidates.append(vt_score)
            verdict = vt_verdict
        
        # Parse AbuseIPDB results
        abuse_score, abuse_verdict = self._parse_abuseipdb(payload)
        if abuse_score is not None:
            candidates.append(abuse_score)
            if abuse_verdict != Verdict.UNKNOWN.value:
                verdict = abuse_verdict
        
        # Parse OTX results
        otx_score, otx_verdict, otx_fps = self._parse_otx(payload)
        if otx_score is not None:
            candidates.append(otx_score)
            if otx_verdict != Verdict.UNKNOWN.value:
                verdict = otx_verdict
            false_positives += otx_fps
            
        # Parse Hybrid Analysis results
        ha_score, ha_verdict = self._parse_hybrid_analysis(payload)
        if ha_score is not None:
            candidates.append(ha_score)
            if ha_verdict != Verdict.UNKNOWN.value:
                verdict = ha_verdict
        
        return candidates, verdict, false_positives
    
    def _update_verdict_counts(self, counts: Dict[str, int], verdict: str):
        if verdict == Verdict.MALICIOUS.value:
            counts["malicious"] += 1
        elif verdict == Verdict.SUSPICIOUS.value:
            counts["suspicious"] += 1
        elif verdict in (Verdict.BENIGN.value, Verdict.FALSE_POSITIVE.value):
            counts["harmless"] += 1
        else:
            counts["unknown"] += 1
        
    def _determine_final_verdict(self, counts: Dict[str, int], total_sources: int) -> str:
        if counts["malicious"] > total_sources / 2:
            return Verdict.MALICIOUS.value
        elif counts["suspicious"] > 0:
            return Verdict.SUSPICIOUS.value
        elif counts["false_positives"] > 0 and counts["malicious"] == 0 and counts["suspicious"] == 0:
            return Verdict.FALSE_POSITIVE.value
        elif counts["harmless"] > 0:
            return Verdict.BENIGN.value
        return Verdict.UNKNOWN.value
    
    '''
    PARSING FUNCTIONS FOR EACH SOURCE - These functions extract relevant metrics and verdicts from each source's response
    '''
    def _parse_virustotal(self, data: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
        if "malicious" not in data:
            return None, None
        
        malicious = data.get("malicious", 0) or 0
        harmless = data.get("harmless", 0) or 0
        suspicious = data.get("suspicious", 0) or 0
        total_votes = malicious + harmless + suspicious
        
        scores = min(100.0, (malicious / total_votes) * 100 if total_votes > 0 else None)
        
        if malicious > 0:
            return scores, Verdict.MALICIOUS.value
        elif suspicious > 0:
            return scores, Verdict.SUSPICIOUS.value
        return scores, Verdict.BENIGN.value
    
    def _parse_abuseipdb(self, data: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
        abuse_score = data.get("abuse_confidence_score") or data.get("abuseConfidenceScore")
        if abuse_score is None:
            return None, None
            
        try:
            score = max(0.0, min(100.0, float(abuse_score)))
            if score > 75: return score, Verdict.MALICIOUS.value
            if score > 25: return score, Verdict.SUSPICIOUS.value
            return score, Verdict.BENIGN.value
        except (TypeError, ValueError):
            return None, None
        
    def _parse_otx(self, data: Dict[str, Any]) -> Tuple[Optional[float], Optional[str], int]:
        fp_count = data.get("false_positive_count", 0) or 0
        if not fp_count and isinstance(data.get("false_positive"), list):
            fp_count = len(data.get("false_positive", []))
            
        fp_count = int(fp_count)
        
        if "reputation" not in data:
            return None, None, fp_count
            
        try:
            reputation = float(data.get("reputation", 0) or 0)
            score = max(0.0, min(100.0, abs(reputation)))
            
            if reputation >= 50: return score, Verdict.MALICIOUS.value
            if reputation > 0: return score, Verdict.SUSPICIOUS.value
            return score, Verdict.BENIGN.value
        except (TypeError, ValueError):
            return None, None, fp_count

    def _parse_hybrid_analysis(self, source_name: str, data: Dict[str, Any]) -> Tuple[Optional[float], Optional[str]]:
        is_hybrid = data.get("provider") == EnrichmentSource.HYBRID_ANALYSIS.value or source_name.lower() == EnrichmentSource.HYBRID_ANALYSIS.value
        if not (is_hybrid or "threat_score" in data or "submissions" in data):
            return None, None

        scores = []
        if threat_score := data.get("threat_score"):
            try: scores.append(float(threat_score))
            except (TypeError, ValueError): pass

        submissions = data.get("submissions")
        if isinstance(submissions, list):
            for sub in submissions:
                if isinstance(sub, dict) and (sub_score := sub.get("threat_score")) is not None:
                    try: scores.append(float(sub_score))
                    except (TypeError, ValueError): pass

        score = max(scores) if scores else None
        verdict = None

        if score is not None:
            score = max(0.0, min(100.0, score))
            if score >= 75: verdict = Verdict.MALICIOUS.value
            elif score >= 30: verdict = Verdict.SUSPICIOUS.value
            else: verdict = Verdict.BENIGN.value

        verdict_text = str(data.get("verdict", "")).lower()
        if verdict_text:
            if any(t in verdict_text for t in ["malicious", "malware", "threat"]):
                verdict = Verdict.MALICIOUS.value
            elif any(t in verdict_text for t in ["suspicious", "gray", "grey"]) and verdict != Verdict.MALICIOUS.value:
                verdict = Verdict.SUSPICIOUS.value

        return score, verdict
        
    async def _fetch_from_source(self, name: str, coro) -> Dict[str, Any]:
            try:
                data = await coro
                return {"source": name, "data": data}
            except EnrichmentError as e:
                self.logger.error("Business error from source", source=name, error=str(e))
                return {"source": name, "data": {"error": e.message, "code": e.code.value}}
            except Exception as e:
                self.logger.error("Unexpected error from source", source=name, error=str(e))
            return {"source": name, "data": {"error": "Internal source error", "code": ErrorCode.INTERNAL_ERROR}}
        
    async def get_reputation(self, value: str, ioc_type: str, sources: List[str]) -> Dict[str, Any]:
        """
        Get a simple reputation score for an IoC based on enrichment results from multiple sources
        Args:
            value (str): The IoC value to check
            ioc_type (str): The type of IoC (ip, domain, hash, url, file_path)
            sources (List[str]): List of sources to query for enrichment

        Returns:
            Dict[str, Any]: A dictionary containing the IoC value, calculated reputation score, and a simple verdict (malicious/benign)
        """
        full_report = await self.enrich_ioc(value, ioc_type, sources)
            
        reputation_score = self._calc_reputation_score(full_report)
        return {
            "value": value,
            "reputation": reputation_score,
            "verdict": "malicious" if reputation_score > 10 else "benign",
        }
        
    def _calc_reputation_score(self, report: Dict) -> Dict[str, float]:
        """
        Calculate a reputation score based on the results from different sources
        Args:
            report (Dict): The full enrichment report containing results from all sources

        Returns:
            Dict[str, float]: A dictionary mapping source names to their calculated reputation scores (0-100)
        """
        final_results = report.get("results", {})
        if not isinstance(final_results, dict):
            return {"score": 0.0}
        
        reputation_scores = {}
        for source_name, source_data in final_results.items():
            if not isinstance(source_data, dict):
                continue
            
            if "error" in source_data:
                reputation_scores[source_name] = 0.0
                continue
            
            data = source_data.get("data", {})
            
            # Calculate reputation score with VirusTotal source
            if source_name == "virustotal":
                malicious_count = data.get("malicious", 0) or 0
                harmless_count = data.get("harmless", 0) or 0
                suspicious_count = data.get("suspicious", 0) or 0
                total_votes = malicious_count + harmless_count + suspicious_count
                if total_votes > 0:
                    reputation_scores[source_name] = min(100.0, (malicious_count / total_votes) * 100)
                else:
                    reputation_scores[source_name] = 0.0
             # Calculate reputation score with AbuseIPDB source
            elif source_name == "abuseipdb":
                abuse_score = data.get("abuse_confidence")
                if abuse_score is None:
                    abuse_score = data.get("abuseConfidenceScore")
                if abuse_score is not None:
                    try:
                        abuse_score = float(abuse_score)
                        reputation_scores[source_name] = max(0.0, min(100.0, abuse_score))
                    except (TypeError, ValueError):
                        abuse_score = 0.0
            # Calculate reputation score with OTX source, considering false positives
            elif source_name == "otx":
                otx_score = 0.0
                if "reputation" in data:
                    try:
                        reputation = float(data.get("reputation", 0) or 0)
                        otx_score = max(0.0, min(100.0, abs(reputation)))
                    except (TypeError, ValueError):
                        reputation_scores[source_name] = 0.0
                
                false_positive = data.get("false_positive_count", 0) or 0
                if not false_positive and isinstance(data.get("false_positive"), list):
                    if len(data.get("false_positive", [])) > 10:
                        otx_score = max(otx_score - 20.0, 0.0)
                    else:
                        otx_score = max(0.0, min(100.0, otx_score - len(data.get("false_positive", []))))
            # Calculate reputation score with Hybrid Analysis source
            elif source_name == "hybrid_analysis":
                hybrid_score = 0.0
                sub_scores = 0.0
                threat_score = 0.0
                
                if "threat_score" in data:
                    try:
                        threat_score = float(data.get("threat_score"))
                    except (TypeError, ValueError):
                        threat_score = 0.0
                if "submissions" in data:
                    submissions = data.get("submissions", [])
                    if isinstance(submissions, list):
                        for submission in submissions:
                            if not isinstance(submission, dict):
                                continue
                            sub_score = submission.get("threat_score")
                            if sub_score is not None:
                                try:
                                    sub_score = float(sub_score)
                                    sub_scores = max(sub_scores, sub_score)
                                except (TypeError, ValueError):
                                    continue
                hybrid_score = max(threat_score, sub_scores)
                reputation_scores[source_name] = max(0.0, min(100.0, hybrid_score))
            
            return reputation_scores
        
    async def check_source_health(self, sources: List[str]) -> Dict[str, Any]:
        """
        Check the health status of multiple threat intelligence sources.

        Args:
            sources (List[str]): A list of source names to check. If empty, checks all configured sources.

        Returns:
            Dict[str, Any]: A dictionary mapping source names to their health status (True for healthy, False for unhealthy).
        """
        tasks = []
        source_list = []
            
        for source_name in sources:
            client = self.clients.get(source_name.lower())
            if client:
                tasks.append(client.health_check())
                source_list.append(source_name)
                    
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return {name: res if isinstance(res, bool) else False for name, res in zip(source_list, results)}