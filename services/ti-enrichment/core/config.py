from pydantic import BaseModel, Field, field_validator
from typing import Optional

class APIConfig(BaseModel):
    api_key: str
    timeout: int = Field(default=15, ge=1, le=300)
    enabled: bool = True
    
    @field_validator('api_key')
    @classmethod
    def validate_api_key(cls, v, info):
        """Validate API key is not empty when source is enabled"""
        enabled = info.data.get('enabled', True)
        if enabled and not v:
            raise ValueError("API key is required when source is enabled")
        return v

class VirusTotalConfig(APIConfig):
    base_url: str = "https://www.virustotal.com/api/v3"
    
class AbuseIPDBConfig(APIConfig):
    base_url: str = "https://api.abuseipdb.com/api/v2"
    
class OTXConfig(APIConfig):
    base_url: str = "https://otx.alienvault.com/api/v1"
    
class HybridAnalysisConfig(APIConfig):
    base_url: str = "https://www.hybrid-analysis.com/api/v2"
    
class CacheConfig(BaseModel):
    host: str = Field(default="localhost")
    port: int = Field(default=6379, ge=1, le=65535)
    password: Optional[str] = None
    db: int = Field(default=0, ge=0, le=15)
    ttl_seconds: int = Field(default=86400, ge=60, le=2592000)
    enable: bool = True

class GRPCConfig(BaseModel):
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=50052, ge=1, le=65535)
    max_concurrent_streams: int = Field(default=100, ge=1)
    keepalive_time_ms: int = Field(default=30000)
    keepalive_timeout_ms: int = Field(default=10000)
    
class LoggingConfig(BaseModel):
    level: str = Field(default="info")
    format: str = Field(default="json")
    output: str = Field(default="stdout")  # stdout, file, or syslog
    file_path: Optional[str] = None
    
    @field_validator('level')
    @classmethod
    def validate_level(cls, v):
        valid_levels = ['debug', 'info', 'warning', 'error', 'critical']
        if v.lower() not in valid_levels:
            raise ValueError(f"Log level must be one of {valid_levels}")
        return v.lower()
    
class RateLimitConfig(BaseModel):
    enable: bool = True
    requests_per_minute: int = Field(default=60, ge=1)
    burst_size: int = Field(default=10, ge=1)