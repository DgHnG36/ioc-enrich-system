import asyncio 
from typing import Any, Dict, List, Optional
import aiohttp
from utils.logger import get_logger
from utils.retry import retry
from utils.errors import EnrichmentError, ErrorCode, handle_http_error

class BaseTIClient:
    def __init__(
        self,
        base_url: str,
        api_key: str,
        timeout: int = 15,
    ):
        self.name = self.__class__.__name__
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.logger = get_logger(self.name.lower())
        self._session: Optional[aiohttp.ClientSession] = None
        
    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            # Create connector with connection pooling limits
            connector = aiohttp.TCPConnector(
                limit=100,           # Total connections across all hosts
                limit_per_host=30,   # Connections per host
                ttl_dns_cache=300,   # DNS cache timeout
            )
            self._session = aiohttp.ClientSession(
                timeout=self.timeout,
                connector=connector,
                headers=self._get_default_headers()
            )
        return self._session
    
    async def aclose(self):
        """Close aiohttp session (async context manager cleanup)"""
        if self._session and not self._session.closed:
            await self._session.close()
    
    def _get_default_headers(self) -> Dict[str, str]:
        return {"Accept": "application/json"}
        
    @retry(max_attempts=3, retryable_exceptions=(aiohttp.ClientError, asyncio.TimeoutError))
    async def _request(self, method: str, endpoint: str, **kwargs) -> Any:
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        session = await self._get_session()
        
        start_time = asyncio.get_event_loop().time()
        try:
            async with session.request(method, url, **kwargs) as response:
                duration = (asyncio.get_event_loop().time() - start_time) * 1000
                self.logger.log_external_api_call(
                    source=self.name,
                    endpoint=endpoint,
                    duration_ms=duration,
                    status_code=response.status,
                )
                
                if response.status >= 400:
                    error_text = await response.text()
                    raise handle_http_error(
                        status_code=response.status,
                        response_text=error_text,
                        source=self.name
                    )
                return await response.json()
        except asyncio.TimeoutError as e:
            self.logger.error("Timeout calling source", source=self.name, endpoint=endpoint)
            raise EnrichmentError(ErrorCode.TIMEOUT, f"Request to {self.name} timed out", source=self.name)
        except aiohttp.ClientError as e:
            self.logger.error("Network error calling source", source=self.name, error=str(e))
            raise EnrichmentError(ErrorCode.EXTERNAL_API_ERROR, f"Network error: {str(e)}", source=self.name)

    async def get_report(self, value: str, ioc_type: str) -> Dict[str, Any]:
        method_name = f"get_{ioc_type}_report"
        method = getattr(self, method_name, None)
        
        if not method:
            raise EnrichmentError(
                ErrorCode.NOT_IMPLEMENTED,
                f"{method_name} is not implemented in {self.name}",
                source=self.name
            )
        
        return await method(value)

    # INTERFACE METHODS - To be implemented by subclasses
    async def get_ip_report(self, ip: str) -> Dict[str, Any]:
        raise EnrichmentError(ErrorCode.NOT_IMPLEMENTED, f"{self.name} does not support IP enrichment")
    
    async def get_domain_report(self, domain: str) -> Dict[str, Any]:
        raise EnrichmentError(ErrorCode.NOT_IMPLEMENTED, f"{self.name} does not support domain enrichment")
    
    async def get_hash_report(self, hash_value: str) -> Dict[str, Any]:
        raise EnrichmentError(ErrorCode.NOT_IMPLEMENTED, f"{self.name} does not support hash enrichment")
    
    async def get_url_report(self, url: str) -> Dict[str, Any]:
        raise EnrichmentError(ErrorCode.NOT_IMPLEMENTED, f"{self.name} does not support URL enrichment")
    
    async def get_file_path_report(self, file_path: str) -> Dict[str, Any]:
        raise EnrichmentError(ErrorCode.NOT_IMPLEMENTED, f"{self.name} does not support file path enrichment")
    
    async def get_reputation(self, value: str, ioc_type: str) -> Dict[str, Any]:
        return self.get_report(value, ioc_type)
    
    async def get_batch_report(self, iocs: Dict[str, str]) -> List[Dict[str, Any]]:
        values = list(iocs.keys())
        tasks = [self.get_report(val, ioc_type) for val, ioc_type in iocs.items()]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        batch_results = {}
        for val, res in zip(values, results):
            if isinstance(res, Exception):
               batch_data = {"error": str(res)}
            else:
               batch_data = res
            batch_results[val] = batch_data
                
        return batch_results    
            
    
    async def get_source_health(self) -> bool:
        try:
            await self._get_session()
            return True
        except Exception:
            return False
    
    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()