from typing import Optional
from enum import Enum
import grpc

class ErrorCode(Enum):
    INVALID_INPUT = "INVALID_INPUT"
    UNAUTHORIZED = "UNAUTHORIZED"
    NOT_FOUND = "NOT_FOUND"
    RATE_LIMIT_EXCEED = "RATE_LIMIT_EXCEED"
    EXTERNAL_API_ERROR = "EXTERNAL_API_ERROR"
    TIMEOUT = "TIMEOUT"
    NOT_SUPPORTED = "NOT_SUPPORTED"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    
class EnrichmentError(Exception):
    def __init__(
        self,
        code: ErrorCode,
        message: str,
        source: Optional[str] = None,
    ):
        self.code = code
        self.message = message
        self.source = source
        super().__init__(self.message)
    
def handle_http_error(status_code: int, response_text: str, source: str) -> EnrichmentError:
    if status_code in [401, 403]:
        return EnrichmentError(
            ErrorCode.UNAUTHORIZED,
            f"API key is invalid or lacks permissions in {source}: {response_text}",
            source=source
        )
    elif status_code == 404:
        return EnrichmentError(
            ErrorCode.NOT_FOUND,
            f"Resource not found in {source}: {response_text}",
            source=source
        )
    elif status_code == 429:
        return EnrichmentError(
            ErrorCode.RATE_LIMIT_EXCEED,
            f"Rate limit exceeded in {source}: {response_text}",
            source=source
        )
    elif status_code == 408:
        return EnrichmentError(
            ErrorCode.TIMEOUT,
            f"Request timeout in {source}: {response_text}",
            source=source
        )
    elif status_code in [400, 422]:
        return EnrichmentError(
            ErrorCode.INVALID_INPUT,
            f"Invalid input in {source}: {response_text}",
            source=source
        )
    elif status_code == 501:
        return EnrichmentError(
            ErrorCode.NOT_IMPLEMENTED,
            f"Feature not implemented in {source}: {response_text}",
            source=source
        )
    elif status_code in [408, 504]:
        return EnrichmentError(ErrorCode.TIMEOUT, f"Timeout from {source}", source)
    elif status_code in [500, 502, 503]:
        return EnrichmentError(ErrorCode.EXTERNAL_API_ERROR, f"Upstream service error ({status_code}) from {source}", source)
    else:
        return EnrichmentError(
            ErrorCode.EXTERNAL_API_ERROR,
            f"External API error in {source} (status {status_code}): {response_text}",
            source=source
        ) 
    
def get_grpc_status(error: Exception) -> grpc.StatusCode:
    if isinstance(error, EnrichmentError):
        mapping = {
            ErrorCode.UNAUTHORIZED: grpc.StatusCode.UNAUTHENTICATED,
            ErrorCode.NOT_IMPLEMENTED: grpc.StatusCode.UNIMPLEMENTED,
            ErrorCode.INVALID_INPUT: grpc.StatusCode.INVALID_ARGUMENT,
            ErrorCode.NOT_FOUND: grpc.StatusCode.NOT_FOUND,
            ErrorCode.RATE_LIMIT_EXCEED: grpc.StatusCode.RESOURCE_EXHAUSTED,
            ErrorCode.EXTERNAL_API_ERROR: grpc.StatusCode.UNAVAILABLE,
            ErrorCode.TIMEOUT: grpc.StatusCode.DEADLINE_EXCEEDED,
            ErrorCode.NOT_SUPPORTED: grpc.StatusCode.UNIMPLEMENTED,
            ErrorCode.INTERNAL_ERROR: grpc.StatusCode.INTERNAL,
        }
        
        return mapping.get(error.code, grpc.StatusCode.INTERNAL)
    
    if isinstance(error, NotImplementedError):
        return grpc.StatusCode.UNIMPLEMENTED
    return grpc.StatusCode.INTERNAL