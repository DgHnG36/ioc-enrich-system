import os
import sys
import types
import logging
from enum import Enum


BASE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "services", "ti-enrichment")
)

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


# Stub pythonjsonlogger if missing so utils.logger can import in minimal test env.
if "pythonjsonlogger" not in sys.modules:
    jsonlogger_module = types.ModuleType("pythonjsonlogger.jsonlogger")

    class JsonFormatter(logging.Formatter):
        def add_fields(self, log_record, record, message_dict):
            if isinstance(message_dict, dict):
                log_record.update(message_dict)

        def format(self, record):
            return record.getMessage()

    jsonlogger_module.JsonFormatter = JsonFormatter

    pkg_module = types.ModuleType("pythonjsonlogger")
    pkg_module.jsonlogger = jsonlogger_module
    sys.modules["pythonjsonlogger"] = pkg_module
    sys.modules["pythonjsonlogger.jsonlogger"] = jsonlogger_module


# Stub grpc if missing to support utils.errors mapping tests.
if "grpc" not in sys.modules:
    grpc_module = types.ModuleType("grpc")

    class StatusCode(Enum):
        UNAUTHENTICATED = "UNAUTHENTICATED"
        UNIMPLEMENTED = "UNIMPLEMENTED"
        INVALID_ARGUMENT = "INVALID_ARGUMENT"
        NOT_FOUND = "NOT_FOUND"
        RESOURCE_EXHAUSTED = "RESOURCE_EXHAUSTED"
        UNAVAILABLE = "UNAVAILABLE"
        DEADLINE_EXCEEDED = "DEADLINE_EXCEEDED"
        INTERNAL = "INTERNAL"

    grpc_module.StatusCode = StatusCode
    sys.modules["grpc"] = grpc_module


# Stub redis.asyncio for type-hint imports in utils modules.
if "redis" not in sys.modules:
    redis_module = types.ModuleType("redis")
    redis_asyncio_module = types.ModuleType("redis.asyncio")

    class Redis:  # pragma: no cover - structural stub only
        pass

    redis_asyncio_module.Redis = Redis
    redis_module.asyncio = redis_asyncio_module
    sys.modules["redis"] = redis_module
    sys.modules["redis.asyncio"] = redis_asyncio_module


# Stub aiohttp for client-base tests when dependency is missing.
if "aiohttp" not in sys.modules:
    aiohttp_module = types.ModuleType("aiohttp")

    class ClientError(Exception):
        pass

    class ClientTimeout:
        def __init__(self, total=None):
            self.total = total

    class TCPConnector:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    class ClientSession:
        def __init__(self, *args, **kwargs):
            self.closed = False

        async def close(self):
            self.closed = True

    aiohttp_module.ClientError = ClientError
    aiohttp_module.ClientTimeout = ClientTimeout
    aiohttp_module.TCPConnector = TCPConnector
    aiohttp_module.ClientSession = ClientSession
    sys.modules["aiohttp"] = aiohttp_module


# Stub pydantic for environments without dependency; enough for model module import.
if "pydantic" not in sys.modules:
    pydantic_module = types.ModuleType("pydantic")

    class BaseModel:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    def Field(default=None, **kwargs):
        if default is not None:
            return default
        if "default_factory" in kwargs and callable(kwargs["default_factory"]):
            try:
                return kwargs["default_factory"]()
            except Exception:
                return None
        return None

    def field_validator(*_args, **_kwargs):
        def decorator(fn):
            return fn
        return decorator

    class ConfigDict(dict):
        pass

    pydantic_module.BaseModel = BaseModel
    pydantic_module.Field = Field
    pydantic_module.field_validator = field_validator
    pydantic_module.ConfigDict = ConfigDict
    sys.modules["pydantic"] = pydantic_module
