import asyncio
import random
import time
from functools import wraps
from typing import Callable, TypeVar, Any, Tuple

from utils.logger import get_logger

logger = get_logger("retry_error")
T = TypeVar('T')

class RetryError(Exception):
    """Lỗi cuối cùng sau khi đã thử mọi nỗ lực retry không thành công"""
    pass

def calculate_backoff(
    attempt: int,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    jitter: bool = True
) -> float:
    """Tính toán thời gian chờ theo lũy thừa kèm Jitter (tránh thundering herd)"""
    # Exponential backoff: 1s, 2s, 4s, 8s...
    delay = min(base_delay * (2 ** attempt), max_delay)
    
    if jitter:
        # Full Jitter: random giữa 0 và delay
        delay = random.uniform(0, delay)
    
    return delay

def retry(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 30.0,
    retryable_exceptions: Tuple[type[Exception], ...] = (Exception,),
    use_jitter: bool = True
):
    """
    Decorator đa năng hỗ trợ cả Sync và Async functions.
    Tự động retry với backoff khi gặp các exception nằm trong list.
    """
    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            last_err = None
            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except retryable_exceptions as e:
                    last_err = e
                    if attempt == max_attempts - 1:
                        break
                    
                    delay = calculate_backoff(attempt, base_delay, max_delay, use_jitter)
                    logger.warning(
                        f"Retry attempt {attempt + 1}/{max_attempts} for {func.__name__} "
                        f"after {delay:.2f}s due to {type(e).__name__}"
                    )
                    await asyncio.sleep(delay)
            
            raise RetryError(f"Function {func.__name__} failed after {max_attempts} attempts") from last_err

        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            last_err = None
            for attempt in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except retryable_exceptions as e:
                    last_err = e
                    if attempt == max_attempts - 1:
                        break
                    
                    delay = calculate_backoff(attempt, base_delay, max_delay, use_jitter)
                    logger.warning(
                        f"Retry attempt {attempt + 1}/{max_attempts} for {func.__name__} "
                        f"after {delay:.2f}s due to {type(e).__name__}"
                    )
                    time.sleep(delay)
            
            raise RetryError(f"Function {func.__name__} failed after {max_attempts} attempts") from last_err

        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

    return decorator

async def retry_async(
    func: Callable[..., Any],
    *args,
    max_attempts: int = 3,
    retryable_exceptions: Tuple[type[Exception], ...] = (Exception,),
    **kwargs
) -> Any:
    """Helper cho phép retry một async call nhanh mà không cần decorator"""
    last_err = None
    for attempt in range(max_attempts):
        try:
            return await func(*args, **kwargs)
        except retryable_exceptions as e:
            last_err = e
            if attempt < max_attempts - 1:
                delay = calculate_backoff(attempt)
                await asyncio.sleep(delay)
            else:
                break
    raise RetryError(f"Async call failed after {max_attempts} attempts") from last_err