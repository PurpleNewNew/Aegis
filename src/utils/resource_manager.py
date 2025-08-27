"""
Aegis框架的资源管理工具
提供清理机制、上下文管理器和资源跟踪
"""

import asyncio
import gc
import weakref
from contextlib import asynccontextmanager
from typing import Any, Dict, Optional, Set, AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
from playwright.async_api import Browser, BrowserContext, Page
import tracemalloc

logger = logging.getLogger(__name__)


@dataclass
class ResourceInfo:
    """关于被跟踪资源的信息"""
    resource_id: str
    resource_type: str
    created_at: datetime
    last_accessed: datetime
    resource: Any
    metadata: Dict[str, Any] = field(default_factory=dict)


class ResourceTracker:
    """跟踪和管理资源并自动清理"""
    
    def __init__(self, max_age_seconds: int = 3600):
        self.max_age = timedelta(seconds=max_age_seconds)
        self.resources: Dict[str, ResourceInfo] = {}
        self.weak_refs: Dict[str, weakref.ref] = {}
        self._cleanup_task: Optional[asyncio.Task] = None
        self._running = False
        
    def add_resource(self, resource_id: str, resource: Any, resource_type: str, **metadata) -> None:
        """添加要跟踪的资源"""
        now = datetime.now()
        info = ResourceInfo(
            resource_id=resource_id,
            resource_type=resource_type,
            created_at=now,
            last_accessed=now,
            resource=resource,
            metadata=metadata
        )
        
        self.resources[resource_id] = info
        # 创建弱引用来检测资源何时被垃圾回收
        self.weak_refs[resource_id] = weakref.ref(resource, lambda _: self._on_resource_collected(resource_id))
        
        logger.debug(f"添加资源到跟踪器: {resource_id} ({resource_type})")
    
    def update_access(self, resource_id: str) -> None:
        """更新资源的最后访问时间"""
        if resource_id in self.resources:
            self.resources[resource_id].last_accessed = datetime.now()
    
    def get_resource(self, resource_id: str) -> Optional[Any]:
        """获取被跟踪的资源"""
        if resource_id in self.resources:
            self.update_access(resource_id)
            return self.resources[resource_id].resource
        return None
    
    def remove_resource(self, resource_id: str) -> bool:
        """从跟踪中移除资源"""
        if resource_id in self.resources:
            del self.resources[resource_id]
            if resource_id in self.weak_refs:
                del self.weak_refs[resource_id]
            logger.debug(f"从跟踪器移除资源: {resource_id}")
            return True
        return False
    
    def _on_resource_collected(self, resource_id: str) -> None:
        """资源被垃圾回收时的回调"""
        logger.debug(f"资源被垃圾回收: {resource_id}")
        self.remove_resource(resource_id)
    
    async def cleanup_expired_resources(self) -> None:
        """清理最近未被访问的资源"""
        now = datetime.now()
        expired_ids = []
        
        for resource_id, info in self.resources.items():
            if now - info.last_accessed > self.max_age:
                expired_ids.append(resource_id)
        
        for resource_id in expired_ids:
            await self._cleanup_resource(resource_id)
    
    async def _cleanup_resource(self, resource_id: str) -> None:
        """清理特定资源"""
        if resource_id not in self.resources:
            return
            
        info = self.resources[resource_id]
        
        try:
            # 特定资源的清理
            if info.resource_type == 'browser_context':
                if hasattr(info.resource, 'close') and not info.resource.closed:
                    await info.resource.close()
            elif info.resource_type == 'page':
                if hasattr(info.resource, 'is_closed') and not info.resource.is_closed():
                    await info.resource.close()
            elif info.resource_type == 'browser':
                if hasattr(info.resource, 'is_connected') and info.resource.is_connected():
                    await info.resource.close()
                    
        except Exception as e:
            logger.error(f"清理资源 {resource_id} 时出错: {e}")
        finally:
            self.remove_resource(resource_id)
    
    async def cleanup_all(self) -> None:
        """清理所有被跟踪的资源"""
        logger.info(f"清理所有 {len(self.resources)} 个被跟踪的资源")
        
        # 为所有资源创建清理任务
        cleanup_tasks = []
        for resource_id in list(self.resources.keys()):
            cleanup_tasks.append(self._cleanup_resource(resource_id))
        
        # 并发运行清理任务并设置超时
        if cleanup_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*cleanup_tasks, return_exceptions=True),
                    timeout=30.0
                )
            except asyncio.TimeoutError:
                logger.warning("资源清理超时")
    
    async def start_cleanup_task(self, interval_seconds: int = 300) -> None:
        """启动后台清理任务"""
        if self._cleanup_task and not self._cleanup_task.done():
            return
            
        self._running = True
        self._cleanup_task = asyncio.create_task(self._cleanup_loop(interval_seconds))
        logger.info(f"启动资源清理任务，间隔 {interval_seconds} 秒")
    
    async def stop_cleanup_task(self) -> None:
        """停止后台清理任务"""
        self._running = False
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
        logger.info("停止资源清理任务")
    
    async def _cleanup_loop(self, interval_seconds: int) -> None:
        """主清理循环"""
        while self._running:
            try:
                await asyncio.sleep(interval_seconds)
                await self.cleanup_expired_resources()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"清理循环中出错: {e}")


class BrowserResourceManager:
    """管理浏览器资源并正确清理"""
    
    def __init__(self, max_context_age: int = 3600):
        self.tracker = ResourceTracker(max_age_seconds=max_context_age)
        self.context_counter = 0
        self.page_counter = 0
        
    async def start(self) -> None:
        """启动资源管理"""
        await self.tracker.start_cleanup_task()
    
    async def stop(self) -> None:
        """停止资源管理并清理所有资源"""
        await self.tracker.stop_cleanup_task()
        await self.tracker.cleanup_all()
    
    @asynccontextmanager
    async def create_context(self, browser: Browser, **context_options) -> AsyncIterator[BrowserContext]:
        """浏览器上下文的上下文管理器"""
        self.context_counter += 1
        context_id = f"context_{self.context_counter}"
        
        try:
            context = await browser.new_context(**context_options)
            self.tracker.add_resource(
                context_id, 
                context, 
                'browser_context',
                browser_id=id(browser)
            )
            
            yield context
            
        finally:
            # 如果未显式关闭，上下文将由跟踪器清理
            pass
    
    @asynccontextmanager
    async def create_page(self, context: BrowserContext, **page_options) -> AsyncIterator[Page]:
        """页面的上下文管理器"""
        self.page_counter += 1
        page_id = f"page_{self.page_counter}"
        
        try:
            page = await context.new_page(**page_options)
            self.tracker.add_resource(
                page_id,
                page,
                'page',
                context_id=id(context)
            )
            
            yield page
            
        finally:
            # 如果未显式关闭，页面将由跟踪器清理
            pass


class MemoryMonitor:
    """监控内存使用情况并在需要时触发清理"""
    
    def __init__(self, memory_limit_mb: int = 1024, check_interval: int = 60):
        self.memory_limit = memory_limit_mb * 1024 * 1024  # 转换为字节
        self.check_interval = check_interval
        self._monitor_task: Optional[asyncio.Task] = None
        self._running = False
        self._callbacks: Set[callable] = set()
        
    def add_cleanup_callback(self, callback: callable) -> None:
        """添加内存限制达到时要调用的回调"""
        self._callbacks.add(callback)
    
    def remove_cleanup_callback(self, callback: callable) -> None:
        """移除清理回调"""
        self._callbacks.discard(callback)
    
    async def start_monitoring(self) -> None:
        """启动内存监控"""
        if self._monitor_task and not self._monitor_task.done():
            return
            
        tracemalloc.start()
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info(f"启动内存监控，限制为 {self.memory_limit/1024/1024}MB")
    
    async def stop_monitoring(self) -> None:
        """停止内存监控"""
        self._running = False
        if self._monitor_task and not self._monitor_task.done():
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        tracemalloc.stop()
        logger.info("停止内存监控")
    
    async def _monitor_loop(self) -> None:
        """主监控循环"""
        while self._running:
            try:
                await asyncio.sleep(self.check_interval)
                
                # 获取当前内存使用情况
                current, peak = tracemalloc.get_traced_memory()
                
                if current > self.memory_limit:
                    logger.warning(f"内存限制已超过: {current/1024/1024:.1f}MB > {self.memory_limit/1024/1024:.1f}MB")
                    
                    # 触发清理回调
                    for callback in self._callbacks:
                        try:
                            if asyncio.iscoroutinefunction(callback):
                                await callback()
                            else:
                                callback()
                        except Exception as e:
                            logger.error(f"内存清理回调中出错: {e}")
                    
                    # 强制垃圾回收
                    gc.collect()
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"内存监控中出错: {e}")


# 全局实例
_browser_resource_manager: Optional[BrowserResourceManager] = None
_memory_monitor: Optional[MemoryMonitor] = None


def get_browser_resource_manager() -> BrowserResourceManager:
    """获取全局浏览器资源管理器"""
    global _browser_resource_manager
    if _browser_resource_manager is None:
        _browser_resource_manager = BrowserResourceManager()
    return _browser_resource_manager


def get_memory_monitor() -> MemoryMonitor:
    """获取全局内存监控器"""
    global _memory_monitor
    if _memory_monitor is None:
        _memory_monitor = MemoryMonitor()
    return _memory_monitor


async def initialize_resource_management() -> None:
    """初始化全局资源管理"""
    manager = get_browser_resource_manager()
    monitor = get_memory_monitor()
    
    # 将内存监控器链接到资源管理器
    monitor.add_cleanup_callback(manager.cleanup_expired_resources)
    
    # 启动两个服务
    await manager.start()
    await monitor.start_monitoring()


async def cleanup_all_resources() -> None:
    """清理所有被管理的资源"""
    global _browser_resource_manager, _memory_monitor
    
    if _browser_resource_manager:
        await _browser_resource_manager.stop()
        _browser_resource_manager = None
    
    if _memory_monitor:
        await _memory_monitor.stop_monitoring()
        _memory_monitor = None