from pydantic import BaseModel, Field, field_validator
import os
from functools import lru_cache
from core.config import (
    VirusTotalConfig,
    AbuseIPDBConfig,
    OTXConfig,
    HybridAnalysisConfig,
    CacheConfig,
    GRPCConfig,
    LoggingConfig,
    RateLimitConfig
)

class Settings(BaseModel):
    """Main application settings"""
    environment: str = Field(default="development")
    service_name: str = Field(default="ti-enrichment")
    version: str = Field(default="1.0.0")
    enable_metrics: bool = True

    # API Configurations
    virustotal: VirusTotalConfig
    abuseipdb: AbuseIPDBConfig
    otx: OTXConfig
    hybrid_analysis: HybridAnalysisConfig

    # Infrastructure
    cache: CacheConfig = Field(default_factory=CacheConfig)
    grpc: GRPCConfig = Field(default_factory=GRPCConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)

    class Config:
        env_file = ".env"
        case_sensitive = False

    @field_validator("environment")
    def validate_environment(cls, v):
        if v not in ["development", "staging", "production"]:
            raise ValueError("Invalid environment")
        return v

    def is_production(self) -> bool:
        return self.environment == "production"

    def is_development(self) -> bool:
        return self.environment == "development"


def load_settings_from_env() -> Settings:
    """Load settings from environment variables"""
    return Settings(
        environment=os.getenv("APP_ENV", "development"),
        service_name=os.getenv("APP_SERVICE_NAME", "ti-enrichment"),
        version=os.getenv("APP_VERSION", "1.0.0"),
        enable_metrics=os.getenv("APP_ENABLE_METRICS", "true").lower() == "true",

        # VirusTotal
        virustotal=VirusTotalConfig(
            api_key=os.getenv("VIRUSTOTAL_API_KEY", ""),
            base_url=os.getenv("VIRUSTOTAL_BASE_URL", "https://www.virustotal.com/api/v3"),
            timeout=int(os.getenv("VIRUSTOTAL_TIMEOUT", "15")),
            enabled=os.getenv("VIRUSTOTAL_ENABLED", "true").lower() == "true",
        ),

        # AbuseIPDB
        abuseipdb=AbuseIPDBConfig(
            api_key=os.getenv("ABUSEIPDB_API_KEY", ""),
            base_url=os.getenv("ABUSEIPDB_BASE_URL", "https://api.abuseipdb.com/api/v2"),
            timeout=int(os.getenv("ABUSEIPDB_TIMEOUT", "15")),
            enabled=os.getenv("ABUSEIPDB_ENABLED", "true").lower() == "true",
        ),

        # OTX
        otx=OTXConfig(
            api_key=os.getenv("OTX_API_KEY", ""),
            base_url=os.getenv("OTX_BASE_URL", "https://otx.alienvault.com/api/v1"),
            timeout=int(os.getenv("OTX_TIMEOUT", "15")),
            enabled=os.getenv("OTX_ENABLED", "true").lower() == "true",
        ),

        # Hybrid Analysis
        hybrid_analysis=HybridAnalysisConfig(
            api_key=os.getenv("HYBRID_ANALYSIS_API_KEY", ""),
            base_url=os.getenv("HYBRID_ANALYSIS_BASE_URL", "https://www.hybrid-analysis.com/api/v2"),
            timeout=int(os.getenv("HYBRID_ANALYSIS_TIMEOUT", "15")),
            enabled=os.getenv("HYBRID_ANALYSIS_ENABLED", "true").lower() == "true",
        ),

        # Cache
        cache=CacheConfig(
            host=os.getenv("REDIS_HOST", "localhost"),
            port=int(os.getenv("REDIS_PORT", "6379")),
            password=os.getenv("REDIS_PASSWORD"),
            db=int(os.getenv("REDIS_DB", "0")),
            ttl_seconds=int(os.getenv("CACHE_TTL_SECONDS", "86400")),
            enable=os.getenv("CACHE_ENABLED", "true").lower() == "true",
        ),

        # gRPC
        grpc=GRPCConfig(
            host=os.getenv("GRPC_HOST", "0.0.0.0"),
            port=int(os.getenv("GRPC_PORT", "50052")),
            max_concurrent_streams=int(os.getenv("GRPC_MAX_CONCURRENT_STREAMS", "100")),
            keepalive_time_ms=int(os.getenv("GRPC_KEEPALIVE_TIME_MS", "30000")),
            keepalive_timeout_ms=int(os.getenv("GRPC_KEEPALIVE_TIMEOUT_MS", "10000")),
        ),

        # Logging
        logging=LoggingConfig(
            level=os.getenv("LOG_LEVEL", "info"),
            format=os.getenv("LOG_FORMAT", "json"),
            output=os.getenv("LOG_OUTPUT", "stdout"),
            file_path=os.getenv("LOG_FILE_PATH"),
        ),

        # Rate Limiting
        rate_limit=RateLimitConfig(
            enable=os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true",
            requests_per_minute=int(os.getenv("RATE_LIMIT_RPM", "60")),
            burst_size=int(os.getenv("RATE_LIMIT_BURST", "10")),
        ),
    )


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance"""
    return load_settings_from_env()
