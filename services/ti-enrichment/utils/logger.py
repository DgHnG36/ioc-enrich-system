import contextvars
import logging
import sys
from datetime import datetime, timezone
from typing import Any, Dict
from pythonjsonlogger import jsonlogger

request_id_var = contextvars.ContextVar("request_id", default="n/a")

class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record: Dict[str, Any], record: logging.LogRecord, message_dict: Dict[str, Any]) -> None:
        super().add_fields(log_record, record, message_dict)
        
        log_record["timestamp"] = datetime.now(timezone.utc).isoformat()
        log_record["level"] = record.levelname
        log_record["service"] = "ti-enrichment"
        
        log_record["request_id"] = request_id_var.get()
        
        if "extra_fields" in log_record:
            extra = log_record.pop("extra_fields")
            if isinstance(extra, dict):
                log_record.update(extra)

class Logger:
    def __init__(
        self,
        name: str = "ti-enrichment",
        level: str = "INFO"
    ):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(getattr(logging, level.upper()))
        
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = CustomJsonFormatter("%(timestamp)s %(level)s %(name)s %(message)s")
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
        self.logger.propagate = False
    
    def _log(self, level: str, message: str, **kwargs) -> None:
        getattr(self.logger, level.lower())(message, extra={"extra_fields": kwargs} if kwargs else None)
        
    def info(self, message: str, **kwargs):
        self._log("INFO", message, **kwargs)
    def error(self, message: str, **kwargs):
        self._log("ERROR", message, **kwargs)
    def warning(self, message, **kwargs):
        self._log("WARNING", message, **kwargs)
    def debug(self, message, **kwargs):
        self._log("DEBUG", message, **kwargs)
        
    def log_external_api_call(self, source: str, status_code: int, duration_ms: float, endpoint: str):
        self.info(
            "External API Call",
            type="external_api",
            source=source,
            status_code=status_code,
            duration_ms=round(duration_ms, 2),
            endpoint=endpoint
        )
        
    def log_enrichment_request(self, value: str, ioc_type: str, sources: list):
        self.info(
            "Enrichment Request Start",
            type="enrichment_request",
            ioc_value=value,
            ioc_type=ioc_type,
            sources=sources
        )
# Get logger instance for a given class name
def get_logger(name: str):
    return Logger(name)

def setup_logging(log_level: str = "INFO"):
    """Initialize logging configuration"""
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )