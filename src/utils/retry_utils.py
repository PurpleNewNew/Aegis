"""
通用重试工具
"""
import asyncio
import logging
from functools import wraps
from typing import Callable, Any, Optional, Union

logger = logging.getLogger(__name__)

def retry_async(
    max_attempts: int = 3,
    delay: float = 1.0,
    backoff: float = 2.0,
    exceptions: tuple = (Exception,),
    on_failure: Optional[Callable] = None
):
    """
    异步函数重试装饰器
    
    Args:
        max_attempts: 最大重试次数
        delay: 初始延迟时间（秒）
        backoff: 延迟递增因子
        exceptions: 需要重试的异常类型
        on_failure: 失败时的回调函数
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            current_delay = delay
            
            for attempt in range(max_attempts):
                try:
                    return await func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt == max_attempts - 1:
                        # 最后一次尝试失败
                        if on_failure:
                            await on_failure(e, attempt + 1, *args, **kwargs)
                        logger.error(f"{func.__name__} 最终失败（尝试 {attempt + 1}/{max_attempts}）: {e}")
                        raise
                    
                    logger.warning(f"{func.__name__} 失败（尝试 {attempt + 1}/{max_attempts}），{current_delay}秒后重试: {e}")
                    await asyncio.sleep(current_delay)
                    current_delay *= backoff
            
            # 如果所有尝试都失败，抛出最后一个异常
            raise last_exception
        
        return wrapper
    return decorator


class RetryManager:
    """重试管理器"""
    
    def __init__(
        self,
        max_attempts: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 60.0,
        backoff_factor: float = 2.0,
        jitter: bool = True
    ):
        self.max_attempts = max_attempts
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.backoff_factor = backoff_factor
        self.jitter = jitter
    
    async def execute(
        self,
        func: Callable,
        *args,
        exceptions: tuple = (Exception,),
        **kwargs
    ) -> Any:
        """
        执行带重试的异步函数
        
        Args:
            func: 要执行的函数
            args: 函数参数
            exceptions: 需要重试的异常类型
            kwargs: 函数关键字参数
            
        Returns:
            函数执行结果
        """
        last_exception = None
        current_delay = self.base_delay
        
        for attempt in range(self.max_attempts):
            try:
                return await func(*args, **kwargs)
            except exceptions as e:
                last_exception = e
                
                if attempt == self.max_attempts - 1:
                    logger.error(f"函数 {func.__name__} 执行失败（{self.max_attempts}次尝试）: {e}")
                    raise
                
                # 计算延迟时间
                if self.jitter:
                    import random
                    actual_delay = min(
                        current_delay * (0.5 + random.random()),
                        self.max_delay
                    )
                else:
                    actual_delay = min(current_delay, self.max_delay)
                
                logger.warning(f"函数 {func.__name__} 执行失败，{actual_delay:.1f}秒后重试（{attempt + 1}/{self.max_attempts}）: {e}")
                await asyncio.sleep(actual_delay)
                current_delay *= self.backoff_factor
        
        raise last_exception


async def retry_with_fallback(
    primary_func: Callable,
    fallback_func: Callable,
    *args,
    max_attempts: int = 3,
    **kwargs
) -> Any:
    """
    带有备选方案的重试执行
    
    Args:
        primary_func: 主函数
        fallback_func: 备选函数
        args: 函数参数
        max_attempts: 主函数最大尝试次数
        kwargs: 函数关键字参数
        
    Returns:
        执行结果
    """
    try:
        # 尝试主函数
        return await retry_async(max_attempts=max_attempts)(primary_func)(*args, **kwargs)
    except Exception as primary_error:
        logger.warning(f"主函数执行失败，尝试备选方案: {primary_error}")
        try:
            # 执行备选函数
            return await fallback_func(*args, **kwargs)
        except Exception as fallback_error:
            logger.error(f"备选函数也执行失败: {fallback_error}")
            raise fallback_error from primary_error