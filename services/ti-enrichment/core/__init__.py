"""
Core module for TI enrichment service
Contains configuration management and application settings
"""

from .config import (
    APIConfig,
    VirusTotalConfig,
    AbuseIPDBConfig,
    OTXConfig,
    HybridAnalysisConfig,
    CacheConfig,
    GRPCConfig,
    LoggingConfig,
    RateLimitConfig,
)

from .settings import (
    Settings,
    load_settings_from_env,
    get_settings,
)

__all__ = [
    # Config classes
    "APIConfig",
    "VirusTotalConfig",
    "AbuseIPDBConfig",
    "OTXConfig",
    "HybridAnalysisConfig",
    "CacheConfig",
    "GRPCConfig",
    "LoggingConfig",
    "RateLimitConfig",
    # Settings
    "Settings",
    "load_settings_from_env",
    "get_settings",
]

__version__ = "1.0.0"
