import os

import pytest


def _get_enrichment_addr() -> str:
    return os.getenv("ENRICHMENT_ADDR", "localhost:50052")


def _channel_or_skip(grpc_mod):
    addr = _get_enrichment_addr()
    channel = grpc_mod.insecure_channel(addr)
    try:
        grpc_mod.channel_ready_future(channel).result(timeout=5)
    except Exception as exc:
        pytest.skip(f"ti-enrichment not reachable at {addr}: {exc}")
    return channel


@pytest.mark.integration
@pytest.mark.grpc
def test_ti_enrichment_health_service():
    grpc = pytest.importorskip("grpc")

    health_pb2 = pytest.importorskip("grpc_health.v1.health_pb2")
    health_pb2_grpc = pytest.importorskip("grpc_health.v1.health_pb2_grpc")

    channel = _channel_or_skip(grpc)
    try:
        stub = health_pb2_grpc.HealthStub(channel)
        response = stub.Check(health_pb2.HealthCheckRequest(service=""), timeout=5)
        assert response.status in (
            health_pb2.HealthCheckResponse.SERVING,
            health_pb2.HealthCheckResponse.NOT_SERVING,
        )
    finally:
        channel.close()


@pytest.mark.integration
@pytest.mark.grpc
def test_ti_enrichment_invalid_ip_returns_invalid_argument():
    grpc = pytest.importorskip("grpc")

    pb2 = pytest.importorskip("enrichment.v1.enrichment_service_pb2")
    pb2_grpc = pytest.importorskip("enrichment.v1.enrichment_service_pb2_grpc")

    channel = _channel_or_skip(grpc)
    try:
        stub = pb2_grpc.EnrichmentServiceStub(channel)
        with pytest.raises(grpc.RpcError) as exc:
            stub.EnrichIP(pb2.EnrichIPRequest(ip="not-an-ip", timeout_seconds=3), timeout=5)

        assert exc.value.code() == grpc.StatusCode.INVALID_ARGUMENT
    finally:
        channel.close()
