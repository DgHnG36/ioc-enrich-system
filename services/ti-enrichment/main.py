#!/usr/bin/env python3
"""
Ti-enrichment Service - Main Entry Point

This service provides threat intelligence enrichment from multiple sources:
- VirusTotal
- AbuseIPDB
- AlienVault OTX
- Hybrid Analysis
"""

import asyncio
import sys
import signal
from typing import Dict, Optional

import redis.asyncio as redis

from core.settings import get_settings
from services.enrichment_service import EnrichmentService
from services.virustotal import VirusTotalClient
from services.abuseipdb import AbuseIPDBClient
from services.otx import OTXClient
from services.hybrid_analysis import HybridAnalysisClient
from transports.grpc.grpc_enrich_server import serve
from utils.logger import get_logger, setup_logging
from utils.cache import CacheUtil
from utils.rate_limiter import RateLimiter
from utils.errors import EnrichmentError, ErrorCode


logger = get_logger("main")


async def initialize_clients(settings) -> Dict[str, object]:
    """Initialize TI client instances"""
    clients = {}

    if settings.virustotal.enabled:
        try:
            clients["virustotal"] = VirusTotalClient(
                api_key=settings.virustotal.api_key,
                base_url=settings.virustotal.base_url,
                timeout=settings.virustotal.timeout,
            )
            logger.info("VirusTotal client initialized")
        except Exception as e:
            logger.warning("Failed to initialize VirusTotal client", 
                          error_type=type(e).__name__)

    if settings.abuseipdb.enabled:
        try:
            clients["abuseipdb"] = AbuseIPDBClient(
                api_key=settings.abuseipdb.api_key,
                base_url=settings.abuseipdb.base_url,
                timeout=settings.abuseipdb.timeout,
            )
            logger.info("AbuseIPDB client initialized")
        except Exception as e:
            logger.warning("Failed to initialize AbuseIPDB client",
                          error_type=type(e).__name__)

    if settings.otx.enabled:
        try:
            clients["otx"] = OTXClient(
                api_key=settings.otx.api_key,
                base_url=settings.otx.base_url,
                timeout=settings.otx.timeout,
            )
            logger.info("OTX client initialized")
        except Exception as e:
            logger.warning("Failed to initialize OTX client",
                          error_type=type(e).__name__)

    if settings.hybrid_analysis.enabled:
        try:
            clients["hybrid_analysis"] = HybridAnalysisClient(
                api_key=settings.hybrid_analysis.api_key,
                base_url=settings.hybrid_analysis.base_url,
                timeout=settings.hybrid_analysis.timeout,
            )
            logger.info("Hybrid Analysis client initialized")
        except Exception as e:
            logger.warning("Failed to initialize Hybrid Analysis client",
                          error_type=type(e).__name__)

    if not clients:
        raise EnrichmentError(
            ErrorCode.CONFIGURATION_ERROR,
            "No TI clients initialized. Configure at least one source."
        )

    return clients


async def initialize_rate_limiter(
    settings,
    redis_client: Optional[redis.Redis] = None
) -> Optional[RateLimiter]:
    """Initialize rate limiter"""
    if not settings.rate_limit.enable or redis_client is None:
        return None

    try:
        return RateLimiter(
            redis_client=redis_client,
            max_requests=settings.rate_limit.requests_per_minute,
            window_seconds=60,
            burst_size=settings.rate_limit.burst_size,
        )
    except Exception as e:
        logger.warning("Failed to initialize rate limiter", error=str(e))
        return None


async def graceful_shutdown(signame: str, loop: asyncio.AbstractEventLoop) -> None:
    """Handle graceful shutdown on signal"""
    logger.warning("Received signal, initiating graceful shutdown", signal=signame)
    
    # Cancel all running tasks except current one
    tasks = [task for task in asyncio.all_tasks(loop) if not task.done()]
    for task in tasks:
        task.cancel()
        logger.debug("Cancelled task", task_name=task.get_name())
    
    # Wait for all tasks to complete cancellation
    await asyncio.gather(*tasks, return_exceptions=True)
    logger.info("All tasks cancelled, shutting down event loop")
    loop.stop()


async def main():
    """Main application entry point"""
    # Load settings
    settings = get_settings()
    logger.info(
        "Starting Ti-enrichment service",
        service_name=settings.service_name,
        version=settings.version,
        environment=settings.environment
    )

    # Initialize logging
    setup_logging(settings.logging.level)

    redis_client = None
    clients = {}
    
    try:
        # Initialize Redis/Cache
        if settings.cache.enable:
            redis_url = f"redis://{settings.cache.host}:{settings.cache.port}"
            if settings.cache.password:
                redis_url = f"redis://:{settings.cache.password}@{settings.cache.host}:{settings.cache.port}"

            try:
                redis_client = await redis.from_url(
                    redis_url,
                    db=settings.cache.db,
                    decode_responses=True
                )
                await redis_client.ping()
                logger.info("Redis connected successfully")
            except Exception as e:
                logger.error("Failed to connect to Redis", error=str(e))
                raise EnrichmentError(ErrorCode.CACHE_ERROR, f"Failed to connect to Redis")

        # Initialize cache utility
        cache = None
        if redis_client and settings.cache.enable:
            cache = CacheUtil(redis_client, ttl=settings.cache.ttl_seconds)
            logger.info("Cache utility initialized")

        # Initialize TI clients
        try:
            clients = await initialize_clients(settings)
            logger.info("Initialized threat intelligence clients", client_count=len(clients))
        except Exception as e:
            logger.error("Failed to initialize TI clients")
            sys.exit(1)

        # Initialize enrichment service
        try:
            enrichment_service = EnrichmentService(cache, clients)
            logger.info("Enrichment service initialized")
        except Exception as e:
            logger.error("Failed to initialize enrichment service")
            sys.exit(1)

        # Initialize rate limiter
        rate_limiter = None
        if settings.rate_limit.enable and redis_client:
            try:
                rate_limiter = await initialize_rate_limiter(settings, redis_client)
                logger.info("Rate limiter initialized")
            except Exception as e:
                logger.warning("Failed to initialize rate limiter, continuing without it")

        # Start gRPC server
        try:
            logger.info(
                "Starting gRPC server",
                host=settings.grpc.host,
                port=settings.grpc.port
            )
            await serve(
                port=settings.grpc.port,
                enrichment_service=enrichment_service,
                logger=logger,
                rate_limiter=rate_limiter,
            )
        except Exception as e:
            logger.error("Failed to start gRPC server", error=str(e), error_type=type(e).__name__)
            sys.exit(1)
    
    except KeyboardInterrupt:
        logger.info("Service interrupted by user")
    except Exception as e:
        logger.error("Fatal error", error_type=type(e).__name__)
    finally:
        # Cleanup
        logger.info("Cleaning up resources...")
        
        # Close client sessions
        for source_name, client in clients.items():
            try:
                await client.aclose()
                logger.info("Closed client", source=source_name)
            except Exception as e:
                logger.error("Error closing client", source=source_name, error_type=type(e).__name__)
        
        # Close Redis connection
        if redis_client:
            try:
                await redis_client.aclose()
                logger.info("Redis connection closed")
            except Exception as e:
                logger.error("Error closing Redis connection", error_type=type(e).__name__)
        
        logger.info("Service shutdown complete")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Service interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error("Fatal error", error=str(e))
        sys.exit(1)

# FIX LATER