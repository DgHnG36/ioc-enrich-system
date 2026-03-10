import asyncio
import signal
import sys
import uuid
import time
from typing import Optional, List, Dict, Any, AsyncIterator

import grpc
from grpc import aio
from grpc_health.v1 import health, health_pb2, health_pb2_grpc
from grpc_reflection.v1alpha import reflection
from google.protobuf.timestamp_pb2 import Timestamp
from google.protobuf.struct_pb2 import Struct
from google.protobuf import json_format

from shared.python.enrichment.v1 import enrichment_service_pb2, enrichment_service_pb2_grpc
from shared.python.enrichment.v1 import enrichment_pb2

from services.enrichment_service import EnrichmentService
from utils.logger import get_logger, Logger
from utils.errors import get_grpc_status, EnrichmentError, ErrorCode
from utils.rate_limiter import RateLimiter


class RequestContext:
    """Request context with metadata"""
    def __init__(self, metadata: dict):
        self.request_id = metadata.get('request-id', str(uuid.uuid4()))
        self.user_id = metadata.get('user-id', 'anonymous')
        self.client_service = metadata.get('client-service', 'ioc-core')
        self.trace_id = metadata.get('trace-id', str(uuid.uuid4()))


class LoggingInterceptor(aio.ServerInterceptor):
    """Logging interceptor for gRPC requests"""
    def __init__(self, logger: Logger):
        self.logger = logger

    async def intercept_service(self, continuation, handler_call_details):
        """Intercept RPC calls and log them"""
        method = handler_call_details.method
        start_time = time.time()

        try:
            handler = await continuation(handler_call_details)
            
            async def log_wrapper(request_or_iterator):
                duration = (time.time() - start_time) * 1000
                self.logger.info(
                    "gRPC OK",
                    method=method,
                    duration_ms=round(duration, 2)
                )
                return await handler(request_or_iterator)
            
            return log_wrapper
        except Exception as e:
            duration = (time.time() - start_time) * 1000
            self.logger.error(
                "gRPC Error",
                method=method,
                error=str(e),
                duration_ms=round(duration, 2)
            )
            raise


class EnrichmentServicer(enrichment_service_pb2_grpc.EnrichmentServiceServicer):
    """Enrichment service gRPC handler"""

    def __init__(
        self,
        enrichment_service: EnrichmentService,
        logger: Logger,
        rate_limiter: Optional[RateLimiter] = None
    ):
        self.service = enrichment_service
        self.logger = logger
        self.rate_limiter = rate_limiter

    async def _check_rate_limit(self, context: aio.ServicerContext, metadata: dict):
        """Check rate limiting"""
        if self.rate_limiter:
            req_ctx = RequestContext(metadata)
            is_allowed, info = await self.rate_limiter.acquire(
                f"{req_ctx.client_service}:{req_ctx.user_id}"
            )
            if not is_allowed:
                self.logger.warning(
                    "Rate limit exceeded",
                    user_id=req_ctx.user_id,
                    client_service=req_ctx.client_service
                )
                await context.abort(
                    grpc.StatusCode.RESOURCE_EXHAUSTED,
                    "Too many requests"
                )

    def _to_proto_timestamp(self, ts: Optional[float]) -> Timestamp:
        """Convert Unix timestamp to protobuf Timestamp"""
        if ts is None:
            ts = time.time()
        timestamp = Timestamp()
        timestamp.FromJsonString(str(int(ts)))
        return timestamp

    def _dict_to_struct(self, data: Dict[str, Any]) -> Struct:
        """Convert dict to protobuf Struct"""
        struct = Struct()
        if data:
            json_format.ParseDict(data, struct, ignore_unknown_fields=True)
        return struct

    def _get_sources_enum(self, source_name: str):
        """Convert source name string to proto enum"""
        source_map = {
            'virustotal': enrichment_pb2.ENRICHMENT_SOURCE_VIRUSTOTAL,
            'abuseipdb': enrichment_pb2.ENRICHMENT_SOURCE_ABUSEIPDB,
            'otx': enrichment_pb2.ENRICHMENT_SOURCE_OTX,
            'hybrid_analysis': enrichment_pb2.ENRICHMENT_SOURCE_HYBRID_ANALYSIS,
        }
        return source_map.get(source_name.lower(), enrichment_pb2.ENRICHMENT_SOURCE_UNSPECIFIED)

    def _get_verdict_enum(self, verdict: str):
        """Convert verdict string to proto enum"""
        verdict_map = {
            'benign': enrichment_pb2.VERDICT_BENIGN,
            'suspicious': enrichment_pb2.VERDICT_SUSPICIOUS,
            'malicious': enrichment_pb2.VERDICT_MALICIOUS,
            'false_positive': enrichment_pb2.VERDICT_FALSE_POSITIVE,
            'unknown': enrichment_pb2.VERDICT_UNKNOWN,
        }
        return verdict_map.get(verdict.lower(), enrichment_pb2.VERDICT_UNSPECIFIED)

    async def EnrichIP(self, request, context: aio.ServicerContext):
        """Enrich an IP address"""
        metadata = dict(context.invocation_metadata())
        await self._check_rate_limit(context, metadata)

        try:
            sources = list(request.sources) if request.sources else None
            timeout = request.timeout_seconds if request.timeout_seconds > 0 else None

            result = await self.service.enrich_ioc(
                value=request.ip,
                ioc_type="ip",
                sources=sources
            )

            results_pb = {}
            for source, data in result.get("results", {}).items():
                if "error" not in (data or {}):
                    results_pb[source] = enrichment_pb2.ThreatIntelData(
                        source=self._get_sources_enum(source),
                        confidence=data.get("abuse_confidence_score", 0) / 100
                        if "abuse_confidence_score" in data else 0.0,
                        reported_at=self._to_proto_timestamp(data.get("last_reported_at")),
                        raw_data=self._dict_to_struct(data)
                    )

            aggregated = result.get("aggregated", {})
            aggregated_pb = enrichment_pb2.AggregatedScore(
                overall_score=aggregated.get("overall_score", 0),
                verdict=self._get_verdict_enum(aggregated.get("verdict", "unknown")),
                total_sources=aggregated.get("total_sources", 0),
                malicious_count=aggregated.get("malicious_count", 0),
            )

            ip_data = enrichment_pb2.IPEnrichmentData(
                ip=request.ip,
                country=result.get("results", {}).get("abuseipdb", {}).get("country_code", ""),
                asn=result.get("results", {}).get("otx", {}).get("asn", ""),
                is_proxy=result.get("results", {}).get("abuseipdb", {}).get("is_proxy", False),
                is_tor=result.get("results", {}).get("abuseipdb", {}).get("is_tor", False),
                is_vpn=result.get("results", {}).get("abuseipdb", {}).get("is_vpn", False),
            )

            return enrichment_service_pb2.EnrichIPResponse(
                ip=request.ip,
                results=results_pb,
                aggregated=aggregated_pb,
                ip_data=ip_data,
                enriched_at=self._to_proto_timestamp(result.get("enriched_at"))
            )
        except EnrichmentError as e:
            status = get_grpc_status(e)
            await context.abort(status, str(e))
        except Exception as e:
            self.logger.error("Error enriching IP", ip=request.ip, error=str(e))
            await context.abort(grpc.StatusCode.INTERNAL, "Internal server error")

    async def EnrichDomain(self, request, context: aio.ServicerContext):
        """Enrich a domain"""
        metadata = dict(context.invocation_metadata())
        await self._check_rate_limit(context, metadata)

        try:
            sources = list(request.sources) if request.sources else None
            result = await self.service.enrich_ioc(
                value=request.domain,
                ioc_type="domain",
                sources=sources
            )

            results_pb = {}
            for source, data in result.get("results", {}).items():
                if "error" not in (data or {}):
                    results_pb[source] = enrichment_pb2.ThreatIntelData(
                        source=self._get_sources_enum(source),
                        confidence=0.0,
                        raw_data=self._dict_to_struct(data)
                    )

            aggregated = result.get("aggregated", {})
            aggregated_pb = enrichment_pb2.AggregatedScore(
                overall_score=aggregated.get("overall_score", 0),
                verdict=self._get_verdict_enum(aggregated.get("verdict", "unknown")),
                total_sources=aggregated.get("total_sources", 0),
                malicious_count=aggregated.get("malicious_count", 0),
            )

            domain_data = enrichment_pb2.DomainEnrichmentData(
                domain=request.domain,
                resolved_ips=result.get("results", {}).get("virustotal", {}).get("resolved_ips", []),
                has_ssl=False,
            )

            return enrichment_service_pb2.EnrichDomainResponse(
                domain=request.domain,
                results=results_pb,
                aggregated=aggregated_pb,
                domain_data=domain_data,
                enriched_at=self._to_proto_timestamp(result.get("enriched_at"))
            )
        except EnrichmentError as e:
            status = get_grpc_status(e)
            await context.abort(status, str(e))
        except Exception as e:
            self.logger.error("Error enriching domain", domain=request.domain, error=str(e))
            await context.abort(grpc.StatusCode.INTERNAL, "Internal server error")

    async def EnrichHash(self, request, context: aio.ServicerContext):
        """Enrich a file hash"""
        metadata = dict(context.invocation_metadata())
        await self._check_rate_limit(context, metadata)

        try:
            sources = list(request.sources) if request.sources else None
            result = await self.service.enrich_ioc(
                value=request.hash,
                ioc_type="hash",
                sources=sources
            )

            results_pb = {}
            for source, data in result.get("results", {}).items():
                if "error" not in (data or {}):
                    results_pb[source] = enrichment_pb2.ThreatIntelData(
                        source=self._get_sources_enum(source),
                        confidence=0.0,
                        raw_data=self._dict_to_struct(data)
                    )

            aggregated = result.get("aggregated", {})
            aggregated_pb = enrichment_pb2.AggregatedScore(
                overall_score=aggregated.get("overall_score", 0),
                verdict=self._get_verdict_enum(aggregated.get("verdict", "unknown")),
                total_sources=aggregated.get("total_sources", 0),
                malicious_count=aggregated.get("malicious_count", 0),
            )

            hash_data = enrichment_pb2.HashEnrichmentData(
                hash=request.hash,
                hash_type=request.hash,  # Simplified
            )

            return enrichment_service_pb2.EnrichHashResponse(
                hash=request.hash,
                results=results_pb,
                aggregated=aggregated_pb,
                hash_data=hash_data,
                enriched_at=self._to_proto_timestamp(result.get("enriched_at"))
            )
        except EnrichmentError as e:
            status = get_grpc_status(e)
            await context.abort(status, str(e))
        except Exception as e:
            self.logger.error("Error enriching hash", hash=request.hash, error=str(e))
            await context.abort(grpc.StatusCode.INTERNAL, "Internal server error")

    async def EnrichURL(self, request, context: aio.ServicerContext):
        """Enrich a URL"""
        metadata = dict(context.invocation_metadata())
        await self._check_rate_limit(context, metadata)

        try:
            sources = list(request.sources) if request.sources else None
            result = await self.service.enrich_ioc(
                value=request.url,
                ioc_type="url",
                sources=sources
            )

            results_pb = {}
            for source, data in result.get("results", {}).items():
                if "error" not in (data or {}):
                    results_pb[source] = enrichment_pb2.ThreatIntelData(
                        source=self._get_sources_enum(source),
                        raw_data=self._dict_to_struct(data)
                    )

            aggregated = result.get("aggregated", {})
            aggregated_pb = enrichment_pb2.AggregatedScore(
                overall_score=aggregated.get("overall_score", 0),
                verdict=self._get_verdict_enum(aggregated.get("verdict", "unknown")),
                total_sources=aggregated.get("total_sources", 0),
            )

            url_data = enrichment_pb2.URLEnrichmentData(
                url=request.url,
            )

            return enrichment_service_pb2.EnrichURLResponse(
                url=request.url,
                results=results_pb,
                aggregated=aggregated_pb,
                url_data=url_data,
                enriched_at=self._to_proto_timestamp(result.get("enriched_at"))
            )
        except EnrichmentError as e:
            status = get_grpc_status(e)
            await context.abort(status, str(e))
        except Exception as e:
            self.logger.error("Error enriching URL", url=request.url, error=str(e))
            await context.abort(grpc.StatusCode.INTERNAL, "Internal server error")

    async def EnrichFilePath(self, request, context: aio.ServicerContext):
        """Enrich a file path"""
        metadata = dict(context.invocation_metadata())
        await self._check_rate_limit(context, metadata)

        try:
            sources = list(request.sources) if request.sources else None
            result = await self.service.enrich_ioc(
                value=request.file_path,
                ioc_type="file_path",
                sources=sources
            )

            results_pb = {}
            for source, data in result.get("results", {}).items():
                if "error" not in (data or {}):
                    results_pb[source] = enrichment_pb2.ThreatIntelData(
                        source=self._get_sources_enum(source),
                        raw_data=self._dict_to_struct(data)
                    )

            aggregated = result.get("aggregated", {})
            aggregated_pb = enrichment_pb2.AggregatedScore(
                overall_score=aggregated.get("overall_score", 0),
                verdict=self._get_verdict_enum(aggregated.get("verdict", "unknown")),
                total_sources=aggregated.get("total_sources", 0),
            )

            file_path_data = enrichment_pb2.FilePathEnrichmentData(
                path=request.file_path,
            )

            return enrichment_service_pb2.EnrichFilePathResponse(
                file_path=request.file_path,
                results=results_pb,
                aggregated=aggregated_pb,
                file_path_data=file_path_data,
                enriched_at=self._to_proto_timestamp(result.get("enriched_at"))
            )
        except EnrichmentError as e:
            status = get_grpc_status(e)
            await context.abort(status, str(e))
        except Exception as e:
            self.logger.error("Error enriching file path", file_path=request.file_path, error=str(e))
            await context.abort(grpc.StatusCode.INTERNAL, "Internal server error")

    async def Enrich(self, request, context: aio.ServicerContext):
        """Generic enrichment for any IoC"""
        # Delegate to specific enrichment methods based on type
        await context.abort(grpc.StatusCode.UNIMPLEMENTED, "Use specific enrichment methods")

    async def EnrichBatch(self, request, context: aio.ServicerContext):
        """Batch enrichment"""
        metadata = dict(context.invocation_metadata())
        await self._check_rate_limit(context, metadata)

        try:
            iocs = {req.value: req.type for req in request.requests}
            sources = list(request.sources) if request.sources else None

            result = await self.service.enrich_batch(iocs, sources)

            batch_results = []
            for value, enrichment_result in result.get("results", {}).items():
                if isinstance(enrichment_result, dict) and "error" not in enrichment_result:
                    aggregated = enrichment_result.get("aggregated", {})
                    agg_pb = enrichment_pb2.AggregatedScore(
                        overall_score=aggregated.get("overall_score", 0),
                        verdict=self._get_verdict_enum(aggregated.get("verdict", "unknown")),
                        total_sources=aggregated.get("total_sources", 0),
                    )
                    batch_results.append(agg_pb)

            return enrichment_service_pb2.BatchEnrichResponse(
                results=batch_results,
                total_processed=len(batch_results),
            )
        except Exception as e:
            self.logger.error("Error in batch enrichment", error=str(e))
            await context.abort(grpc.StatusCode.INTERNAL, "Internal server error")

    async def GetReputation(self, request, context: aio.ServicerContext):
        """Get reputation score"""
        try:
            sources = list(request.sources) if request.sources else None
            result = await self.service.enrich_ioc(
                value=request.value,
                ioc_type=request.value_type,
                sources=sources
            )

            aggregated = result.get("aggregated", {})
            agg_pb = enrichment_pb2.AggregatedScore(
                overall_score=aggregated.get("overall_score", 0),
                verdict=self._get_verdict_enum(aggregated.get("verdict", "unknown")),
                total_sources=aggregated.get("total_sources", 0),
                malicious_count=aggregated.get("malicious_count", 0),
            )

            return enrichment_service_pb2.GetReputationResponse(
                value=request.value,
                aggregated=agg_pb,
            )
        except Exception as e:
            self.logger.error("Error getting reputation", value=request.value, error=str(e))
            await context.abort(grpc.StatusCode.INTERNAL, "Internal server error")

    async def StreamEnrich(self, request_iterator, context: aio.ServicerContext):
        """Stream enrichment"""
        metadata = dict(context.invocation_metadata())

        try:
            async for request in request_iterator:
                await self._check_rate_limit(context, metadata)

                result = await self.service.enrich_ioc(
                    value=request.value,
                    ioc_type=request.type,
                    sources=list(request.sources) if request.sources else None
                )

                aggregated = result.get("aggregated", {})
                agg_pb = enrichment_pb2.AggregatedScore(
                    overall_score=aggregated.get("overall_score", 0),
                    verdict=self._get_verdict_enum(aggregated.get("verdict", "unknown")),
                    total_sources=aggregated.get("total_sources", 0),
                )

                yield enrichment_service_pb2.StreamEnrichResponse(
                    value=request.value,
                    aggregated=agg_pb,
                )
        except Exception as e:
            self.logger.error("Error in stream enrichment", error=str(e))
            await context.abort(grpc.StatusCode.INTERNAL, "Internal server error")

    async def CheckSourceHealth(self, request, context: aio.ServicerContext):
        """Check health of enrichment sources"""
        try:
            sources = list(request.sources) if request.sources else None
            health_status = await self.service.get_source_health(sources)

            source_health = []
            for source, is_healthy in health_status.items():
                source_health.append(
                    enrichment_pb2.SourceHealth(
                        source=self._get_sources_enum(source),
                        is_healthy=is_healthy,
                        last_checked=self._to_proto_timestamp(time.time()),
                    )
                )

            return enrichment_service_pb2.CheckSourceHealthResponse(
                sources=source_health,
                all_healthy=all(health_status.values()),
            )
        except Exception as e:
            self.logger.error("Error checking source health", error=str(e))
            await context.abort(grpc.StatusCode.INTERNAL, "Internal server error")


async def serve(
    port: int,
    enrichment_service: EnrichmentService,
    logger: Logger,
    rate_limiter: Optional[RateLimiter] = None
):
    """Start gRPC server"""
    server = aio.server(
        # NOTE: LoggingInterceptor is currently incompatible with grpc.aio handler contract.
        # Keep server interceptor-free to avoid runtime AttributeError on request handling.
        interceptors=[],
        options=[
            ('grpc.max_send_message_length', 50 * 1024 * 1024),
            ('grpc.max_receive_message_length', 50 * 1024 * 1024),
            ('grpc.max_concurrent_streams', 500),
            ('grpc.keepalive_time_ms', 30000),
            ('grpc.keepalive_timeout_ms', 10000),
            ('grpc.keepalive_permit_without_calls', True),
            ('grpc.http2.max_pings_without_data', 0),
            ('grpc.http2.min_ping_interval_without_data_ms', 10000),
        ]
    )

    servicer = EnrichmentServicer(enrichment_service, logger, rate_limiter)
    enrichment_service_pb2_grpc.add_EnrichmentServiceServicer_to_server(servicer, server)

    health_servicer = health.HealthServicer()
    health_pb2_grpc.add_HealthServicer_to_server(health_servicer, server)

    services = (
        enrichment_service_pb2.DESCRIPTOR.services_by_name[
            'EnrichmentService'
        ].full_name,
        reflection.SERVICE_NAME,
    )
    reflection.enable_server_reflection(services, server)

    # Add port binding - [::] for all interfaces (IPv6 and IPv4 with dual-stack)
    port_addr = f'0.0.0.0:{port}'
    server.add_insecure_port(port_addr)
    
    logger.info("Starting gRPC server", port=port, address=port_addr)
    await server.start()
    logger.info("Enrichment service gRPC server started and listening", port=port, address=port_addr)
    
    # Keep server running
    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        logger.info("Shutting down enrichment service gracefully...")
        await server.stop(5)
