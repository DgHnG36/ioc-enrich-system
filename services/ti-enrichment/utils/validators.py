"""Input validation utilities for IoC enrichment"""
import re
from typing import Dict
from utils.errors import EnrichmentError, ErrorCode


class IoCValidator:
    """Validator for IoC (Indicator of Compromise) values"""
    
    # IP regex pattern (IPv4)
    IP_PATTERN = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    
    # Domain regex pattern
    DOMAIN_PATTERN = re.compile(
        r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$',
        re.IGNORECASE
    )
    
    # Hash patterns
    MD5_PATTERN = re.compile(r'^[a-f0-9]{32}$', re.IGNORECASE)
    SHA1_PATTERN = re.compile(r'^[a-f0-9]{40}$', re.IGNORECASE)
    SHA256_PATTERN = re.compile(r'^[a-f0-9]{64}$', re.IGNORECASE)
    
    # URL pattern (simplified)
    URL_PATTERN = re.compile(
        r'^https?://'
        r'(?:(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}|'
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?'
        r'(?:/[^\s]*)?$',
        re.IGNORECASE
    )
    
    @staticmethod
    def validate_ip(value: str) -> bool:
        """Validate IPv4 address"""
        if not isinstance(value, str) or not value.strip():
            return False
        return bool(IoCValidator.IP_PATTERN.match(value.strip()))
    
    @staticmethod
    def validate_domain(value: str) -> bool:
        """Validate domain name"""
        if not isinstance(value, str) or not value.strip():
            return False
        domain = value.strip().lower()
        # Remove www. if present
        if domain.startswith('www.'):
            domain = domain[4:]
        return bool(IoCValidator.DOMAIN_PATTERN.match(domain))
    
    @staticmethod
    def validate_hash(value: str) -> bool:
        """Validate file hash (MD5, SHA1, or SHA256)"""
        if not isinstance(value, str) or not value.strip():
            return False
        value = value.strip()
        return bool(
            IoCValidator.MD5_PATTERN.match(value) or
            IoCValidator.SHA1_PATTERN.match(value) or
            IoCValidator.SHA256_PATTERN.match(value)
        )
    
    @staticmethod
    def validate_url(value: str) -> bool:
        """Validate URL"""
        if not isinstance(value, str) or not value.strip():
            return False
        return bool(IoCValidator.URL_PATTERN.match(value.strip()))
    
    @staticmethod
    def validate_file_path(value: str) -> bool:
        """Validate file path"""
        if not isinstance(value, str) or not value.strip():
            return False
        # Basic check: should contain path separators and not be empty
        value = value.strip()
        return len(value) > 0 and ('/' in value or '\\' in value)
    
    # Validator mapping
    VALIDATORS: Dict[str, callable] = {
        'ip': validate_ip.__func__,
        'domain': validate_domain.__func__,
        'hash': validate_hash.__func__,
        'url': validate_url.__func__,
        'file_path': validate_file_path.__func__,
    }
    
    @classmethod
    def validate(cls, value: str, ioc_type: str) -> None:
        """
        Validate IoC value against type
        
        Args:
            value: IoC value to validate
            ioc_type: Type of IoC (ip, domain, hash, url, file_path)
            
        Raises:
            EnrichmentError: If validation fails
        """
        if not isinstance(value, str):
            raise EnrichmentError(
                ErrorCode.INVALID_INPUT,
                f"IoC value must be string, got {type(value).__name__}"
            )
        
        if not value.strip():
            raise EnrichmentError(
                ErrorCode.INVALID_INPUT,
                "IoC value cannot be empty"
            )
        
        ioc_type = ioc_type.lower().strip()
        
        if ioc_type not in cls.VALIDATORS:
            raise EnrichmentError(
                ErrorCode.INVALID_INPUT,
                f"Unsupported IoC type: {ioc_type}. "
                f"Supported types: {', '.join(cls.VALIDATORS.keys())}"
            )
        
        validator = cls.VALIDATORS[ioc_type]
        if not validator(value):
            raise EnrichmentError(
                ErrorCode.INVALID_INPUT,
                f"Invalid {ioc_type}: {value}"
            )


def validate_ioc(value: str, ioc_type: str) -> None:
    """Convenience function to validate IoC"""
    IoCValidator.validate(value, ioc_type)
