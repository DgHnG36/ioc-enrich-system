import hashlib
import re
from typing import Optional


def md5(data: str) -> str:
    """Calculate MD5 hash"""
    return hashlib.md5(data.encode()).hexdigest()


def sha1(data: str) -> str:
    """Calculate SHA1 hash"""
    return hashlib.sha1(data.encode()).hexdigest()


def sha256(data: str) -> str:
    """Calculate SHA256 hash"""
    return hashlib.sha256(data.encode()).hexdigest()


def identify_hash_type(hash_value: str) -> Optional[str]:
    """
    Identify hash type based on length and format
    
    Args:
        hash_value: Hash string
    
    Returns:
        Hash type (md5, sha1, sha256) or None
    """
    hash_value = hash_value.lower().strip()
    
    # Check if valid hex string
    if not re.match(r'^[a-f0-9]+$', hash_value):
        return None
    
    length = len(hash_value)
    
    if length == 32:
        return 'md5'
    elif length == 40:
        return 'sha1'
    elif length == 64:
        return 'sha256'
    
    return None


def validate_hash(hash_value: str, hash_type: str) -> bool:
    """
    Validate hash format
    
    Args:
        hash_value: Hash string
        hash_type: Expected hash type
    
    Returns:
        True if valid
    """
    hash_value = hash_value.lower().strip()
    
    patterns = {
        'md5': r'^[a-f0-9]{32}$',
        'sha1': r'^[a-f0-9]{40}$',
        'sha256': r'^[a-f0-9]{64}$'
    }
    
    pattern = patterns.get(hash_type.lower())
    if not pattern:
        return False
    
    return bool(re.match(pattern, hash_value))


def normalize_hash(hash_value: str) -> str:
    """Normalize hash to lowercase"""
    return hash_value.lower().strip()