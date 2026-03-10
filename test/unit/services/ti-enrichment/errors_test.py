import grpc

from utils.errors import (
    EnrichmentError,
    ErrorCode,
    get_grpc_status,
    handle_http_error,
)


def test_handle_http_error_401_maps_to_unauthorized():
    err = handle_http_error(401, "bad token", "VT")
    assert isinstance(err, EnrichmentError)
    assert err.code == ErrorCode.UNAUTHORIZED


def test_handle_http_error_429_maps_rate_limit():
    err = handle_http_error(429, "too many", "OTX")
    assert err.code == ErrorCode.RATE_LIMIT_EXCEED


def test_handle_http_error_500_maps_external_api_error():
    err = handle_http_error(500, "oops", "HA")
    assert err.code == ErrorCode.EXTERNAL_API_ERROR


def test_get_grpc_status_for_enrichment_error():
    err = EnrichmentError(ErrorCode.INVALID_INPUT, "bad input")
    assert get_grpc_status(err) == grpc.StatusCode.INVALID_ARGUMENT


def test_get_grpc_status_for_not_implemented_error():
    assert get_grpc_status(NotImplementedError("x")) == grpc.StatusCode.UNIMPLEMENTED
