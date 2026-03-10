from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from enum import Enum
from pydantic import BaseModel, Field, field_validator, ConfigDict
import ipaddress
import re
from urllib.parse import urlparse

'''
UTILITY FUNCTIONS
utc_now(): return current UTC time
serialize_datetime(): convert datetime to ISO format string for JSON serialization
'''
def utc_now() -> datetime:
    return datetime.now(timezone.utc)

def serialize_datetime(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None

'''
ENUMS for standardizing values across the service
'''
class Verdict(str, Enum):
    UNSPECIFIED = "unspecified"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    FALSE_POSITIVE = "false_positive"
    UNKNOWN = "unknown"

class ThreatCategory(str, Enum):
    UNSPECIFIED = "unspecified"
    MALWARE = "malware"
    BOTNET = "botnet"
    C2 = "c2"
    EXPLOIT = "exploit"
    PHISHING = "phishing"
    SPAM = "spam"

class EnrichmentSource(str, Enum):
    UNSPECIFIED = "unspecified"
    VIRUSTOTAL = "virustotal"
    ABUSEIPDB = "abuseipdb"
    OTX = "otx"
    HYBRID_ANALYSIS = "hybrid_analysis"
    
    @classmethod
    def is_valid(cls, value: str) -> bool:
        return value in cls._value2member_map_
    
class EnrichmentStatus(str, Enum):
    UNSPECIFIED = "unspecified"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"

'''
BASE MODELS
- ThreatIntelData
- AggregatedScore
'''
class ThreatIntelData(BaseModel):
    model_config = ConfigDict(
        use_enum_values=True,
        json_encoders={datetime: serialize_datetime}
    )
    
    source: EnrichmentSource
    threat_id: str = ""
    confidence: float = Field(ge=0.0, le=1.0, default=0.0)
    reported_at: datetime = Field(default_factory=utc_now)
    raw_data: Dict[str, Any] = Field(default_factory=dict)
    
class AggregatedScore(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    
    overall_score: float = Field(ge=0.0, le=1.0, default=0.0)
    verdict: Verdict = Verdict.UNKNOWN
    total_sources: int = 0
    malicious_count: int = 0
        
    def calculate_verdict(self) -> Verdict:
        if self.total_sources == 0:
            return Verdict.UNKNOWN
        
        malicious_ratio = self.malicious_count / self.total_sources
        benign_ratio = (self.total_sources - self.malicious_count) / self.total_sources
        
        if malicious_ratio >= 0.5:
            return Verdict.MALICIOUS
        elif malicious_ratio >= 0.2:
            return Verdict.SUSPICIOUS
        elif benign_ratio >= 0.8:
            return Verdict.BENIGN
        else:
            return Verdict.UNKNOWN
    
'''
SPECIFIC ENRICHMENT MODELS
- IPEnrichmentData
- DomainEnrichmentData
- HashEnrichmentData
- URLEnrichmentData
- FilePathEnrichmentData
'''
# IP MODELS
class IPEnrichmentData(BaseModel):
    ip: str
    asn: Optional[str] = None
    country: Optional[str] = None
    is_proxy: bool = False
    is_tor: bool = False
    is_vpn: bool = False
    
class EnrichIPRequest(BaseModel):
    ip: str
    sources: List[EnrichmentSource] = Field(default_factory=list)
    timeout_seconds: int = 30
    
    @field_validator('ip')
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ipaddress.ip_address(v)
        except ValueError:
            raise ValueError(f'Invalid IP address: {v}')
        return v
    
class EnrichIPResponse(BaseModel):
    ip: str
    results: Dict[str, ThreatIntelData] = Field(default_factory=dict)
    aggregated: Optional[AggregatedScore] = None
    ip_data: Optional[IPEnrichmentData] = None
    enriched_at: datetime = Field(default_factory=utc_now)

# DOMAIN MODELS
class DomainEnrichmentData(BaseModel):
    domain: str
    creation_date: Optional[datetime] = None
    registrar: Optional[str] = None
    resolved_ips: List[str] = Field(default_factory=list)
    has_ssl: bool = False
        
class EnrichDomainRequest(BaseModel):
    domain: str
    sources: List[EnrichmentSource] = Field(default_factory=list)
    timeout_seconds: int = 30
    
    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(domain_pattern, v):
            raise ValueError(f'Invalid domain: {v}')
        return v
    
class EnrichDomainResponse(BaseModel):
    domain: str
    results: Dict[str, ThreatIntelData] = Field(default_factory=dict)
    aggregated: Optional[AggregatedScore] = None
    domain_data: Optional[DomainEnrichmentData] = None
    enriched_at: datetime = Field(default_factory=utc_now)
        
# HASH MODELS
class HashEnrichmentData(BaseModel):
    hash: str
    hash_type: str
    file_size: Optional[int] = None
    file_type: Optional[str] = None
    is_packed: bool = False
    
class EnrichHashRequest(BaseModel):
    hash: str
    hash_type: str = "sha256"
    sources: List[EnrichmentSource] = Field(default_factory=list)
    timeout_seconds: int = 30

    @field_validator('hash')
    @classmethod
    def validate_hash(cls, v: str) -> str:
        if not re.match(r'^[a-fA-F0-9]+$', v):
            raise ValueError(f'Invalid hash format: {v}')
        return v.lower()

    @field_validator('hash_type')
    @classmethod
    def validate_hash_type(cls, v: str) -> str:
        valid_types = ['md5', 'sha1', 'sha256']
        if v.lower() not in valid_types:
            raise ValueError(f'Hash type must be one of: {valid_types}')
        return v.lower()
    
class EnrichHashResponse(BaseModel):
    hash: str
    results: Dict[str, ThreatIntelData] = Field(default_factory=dict)
    aggregated: Optional[AggregatedScore] = None
    hash_data: Optional[HashEnrichmentData] = None
    enriched_at: datetime = Field(default_factory=utc_now)

# URL MODELS
class URLEnrichmentData(BaseModel):
    url: str
    final_url: Optional[str] = None
    redirect_count: int = 0
    has_phishing_indicators: bool = False
    
class EnrichURLRequest(BaseModel):
    url: str
    sources: List[EnrichmentSource] = Field(default_factory=list)
    timeout_seconds: int = 30

    @field_validator('url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        try:
            result = urlparse(v)
            if not all([result.scheme, result.netloc]):
                raise ValueError('Invalid URL')
        except Exception:
            raise ValueError(f'Invalid URL: {v}')
        return v
    
class EnrichURLResponse(BaseModel):
    url: str
    results: Dict[str, ThreatIntelData] = Field(default_factory=dict)
    aggregated: Optional[AggregatedScore] = None
    url_data: Optional[URLEnrichmentData] = None
    enriched_at: datetime = Field(default_factory=utc_now)

# FILE PATH MODELS
class FilePathEnrichmentData(BaseModel):
    path: str
    extension: Optional[str] = None
    is_system_path: bool = False
    is_temp_path: bool = False

class EnrichFilePathRequest(BaseModel):
    file_path: str
    sources: List[EnrichmentSource] = Field(default_factory=list)
    timeout_seconds: int = 30

class EnrichFilePathResponse(BaseModel):
    file_path: str
    results: Dict[str, ThreatIntelData] = Field(default_factory=dict)
    aggregated: Optional[AggregatedScore] = None
    file_path_data: Optional[FilePathEnrichmentData] = None
    enriched_at: datetime = Field(default_factory=utc_now)


'''
GENERAL ENRICHMENT MODELS
'''
class EnrichOptions(BaseModel):
    hash_type: str = ""
    include_file_metadata: bool = False
    force_refresh: bool = False

class EnrichRequest(BaseModel):
    value: str
    type: str
    sources: List[EnrichmentSource] = Field(default_factory=list)
    timeout_seconds: int = 30
    options: EnrichOptions = Field(default_factory=EnrichOptions)
    
class EnrichResponse(BaseModel):
    value: str
    type: str
    results: Dict[str, ThreatIntelData] = Field(default_factory=dict)
    aggregated: Optional[AggregatedScore] = None
    enriched_at: datetime = Field(default_factory=utc_now)

class BatchEnrichRequest(BaseModel):
    requests: List[EnrichRequest]
    max_concurrency: int = 5

    @field_validator('max_concurrency')
    @classmethod
    def validate_concurrency(cls, v: int) -> int:
        if not 1 <= v <= 10:
            raise ValueError('Max concurrency must be between 1 and 10')
        return v

class BatchEnrichResponse(BaseModel):
    responses: List[EnrichResponse]
    total_count: int = 0
    success_count: int = 0
    failed_count: int = 0
    errors: Dict[str, str] = Field(default_factory=dict)
    
'''
REPUTATION AND HEALTH MODELS
'''
class GetReputationRequest(BaseModel):
    value: str
    type: str
    sources: List[EnrichmentSource] = Field(default_factory=list)

class GetReputationResponse(BaseModel):
    source_scores: Dict[str, float] = Field(default_factory=dict)
    aggregated: Optional[AggregatedScore] = None
        
class SourceHealth(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    
    source: EnrichmentSource
    is_healthy: bool = True
    error_message: str = ""
    last_checked: datetime = Field(default_factory=utc_now)

class CheckSourceHealthRequest(BaseModel):
    sources: List[EnrichmentSource] = Field(default_factory=list)

class CheckSourceHealthResponse(BaseModel):
    health_status: Dict[str, SourceHealth] = Field(default_factory=dict)
    overall_healthy: bool = True
        
'''
INTERNAL MODELS (STREAMING AND CACHE)
'''
class StreamEnrichRequest(BaseModel):
    request_id: str
    request: EnrichRequest

class StreamEnrichResponse(BaseModel):
    request_id: str
    success: Optional[EnrichResponse] = None
    error_message: Optional[str] = None

class CachedEnrichmentResult(BaseModel):
    value: str
    type: str
    source: EnrichmentSource
    result: ThreatIntelData
    cached_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime

    def is_expired(self) -> bool:
        return utc_now() > self.expires_at

class EnrichmentError(BaseModel):
    source: EnrichmentSource
    error_code: str
    error_message: str
    is_retryable: bool = False
    retry_after: Optional[int] = None
    timestamp: datetime = Field(default_factory=utc_now)