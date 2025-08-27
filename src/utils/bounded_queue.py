"""
Aegis框架的有界队列实现
提供队列大小限制和背压机制以防止内存耗尽
"""

import asyncio
import logging
from typing import Any, Optional, Union
from collections import deque
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class QueueStats:
    """队列操作统计信息"""
    max_size: int
    current_size: int
    total_enqueued: int = 0
    total_dequeued: int = 0
    total_dropped: int = 0
    high_water_mark: int = 0


class BoundedAsyncQueue:
    """
    具有大小限制和背压机制的有界异步队列
    通过限制队列大小防止内存耗尽
    """
    
    def __init__(self, maxsize: int = 1000, name: str = "UnnamedQueue"):
        """
        初始化有界队列
        
        Args:
            maxsize: 队列中项目的最大数量
            name: 用于日志记录的队列名称
        """
        if maxsize <= 0:
            raise ValueError("队列最大大小必须为正数")
            
        self._queue = asyncio.Queue(maxsize=maxsize)
        self._maxsize = maxsize
        self._name = name
        self._stats = QueueStats(maxsize=maxsize, current_size=0)
        self._get_event = asyncio.Event()
        self._put_event = asyncio.Event()
        
    @property
    def maxsize(self) -> int:
        """获取队列最大大小"""
        return self._maxsize
        
    @property
    def qsize(self) -> int:
        """获取当前队列大小"""
        return self._queue.qsize()
        
    @property
    def stats(self) -> QueueStats:
        """获取队列统计信息"""
        self._stats.current_size = self.qsize
        return self._stats
        
    async def put(self, item: Any, block: bool = True, timeout: Optional[float] = None) -> bool:
        """
        将项目放入队列
        
        Args:
            item: 要放入队列的项目
            block: 如果为True，则在空间可用时阻塞
            timeout: 阻塞时等待的最大时间
            
        Returns:
            如果项目已入队则返回True，如果被丢弃则返回False
        """
        try:
            if block:
                if timeout is not None:
                    await asyncio.wait_for(self._queue.put(item), timeout=timeout)
                else:
                    await self._queue.put(item)
            else:
                self._queue.put_nowait(item)
                
            self._stats.total_enqueued += 1
            self._stats.current_size = self.qsize
            
            # 更新高水位标记
            if self._stats.current_size > self._stats.high_water_mark:
                self._stats.high_water_mark = self._stats.current_size
                if self._stats.high_water_mark > self._maxsize * 0.8:
                    logger.warning(f"队列 '{self._name}' 高水位标记: {self._stats.high_water_mark}/{self._maxsize}")
                    
            self._put_event.set()
            self._put_event.clear()
            return True
            
        except asyncio.QueueFull:
            self._stats.total_dropped += 1
            logger.warning(f"队列 '{self._name}' 已满，丢弃项目 (已丢弃: {self._stats.total_dropped})")
            return False
        except asyncio.TimeoutError:
            self._stats.total_dropped += 1
            logger.warning(f"队列 '{self._name}' 放入超时，丢弃项目")
            return False
            
    async def get(self, block: bool = True, timeout: Optional[float] = None) -> Any:
        """
        从队列中获取项目
        
        Args:
            block: 如果为True，则在项目可用时阻塞
            timeout: 阻塞时等待的最大时间
            
        Returns:
            队列中的项目，如果超时则返回None
        """
        try:
            if block:
                if timeout is not None:
                    item = await asyncio.wait_for(self._queue.get(), timeout=timeout)
                else:
                    item = await self._queue.get()
            else:
                item = self._queue.get_nowait()
                
            self._stats.total_dequeued += 1
            self._stats.current_size = self.qsize
            
            self._get_event.set()
            self._get_event.clear()
            return item
            
        except asyncio.QueueEmpty:
            return None
        except asyncio.TimeoutError:
            return None
            
    def put_nowait(self, item: Any) -> bool:
        """不阻塞地放入项目"""
        return asyncio.run_coroutine_threadsafe(self.put(item, block=False), asyncio.get_event_loop()).result()
        
    def get_nowait(self) -> Any:
        """不阻塞地获取项目"""
        return asyncio.run_coroutine_threadsafe(self.get(block=False), asyncio.get_event_loop()).result()
        
    async def clear(self) -> int:
        """清除队列中的所有项目，返回清除的项目数"""
        cleared = 0
        while not self._queue.empty():
            try:
                self._queue.get_nowait()
                cleared += 1
            except asyncio.QueueEmpty:
                break
                
        self._stats.current_size = 0
        logger.info(f"从队列 '{self._name}' 清除了 {cleared} 个项目")
        return cleared
        
    async def wait_until_empty(self, timeout: Optional[float] = None) -> bool:
        """等待队列变空"""
        if self.qsize() == 0:
            return True
            
        try:
            if timeout is not None:
                await asyncio.wait_for(self._get_event.wait(), timeout=timeout)
            else:
                await self._get_event.wait()
            return self.qsize() == 0
        except asyncio.TimeoutError:
            return False
            
    def is_full(self) -> bool:
        """检查队列是否已满"""
        return self.qsize() >= self._maxsize
        
    def is_empty(self) -> bool:
        """检查队列是否为空"""
        return self.qsize() == 0
        
    def __str__(self) -> str:
        return f"BoundedAsyncQueue(name='{self._name}', size={self.qsize}/{self._maxsize})"


class PriorityBoundedQueue:
    """
    具有优先级的有界队列，用于处理具有优先级的项目
    数字越小优先级越高
    """
    
    def __init__(self, maxsize: int = 1000, name: str = "PriorityQueue"):
        """
        初始化优先级队列
        
        Args:
            maxsize: 队列中项目的最大数量
            name: 用于日志记录的队列名称
        """
        self._maxsize = maxsize
        self._name = name
        self._queue = []  # (priority, item) 元组列表
        self._lock = asyncio.Lock()
        self._not_empty = asyncio.Condition(self._lock)
        self._not_full = asyncio.Condition(self._lock)
        self._stats = QueueStats(maxsize=maxsize, current_size=0)
        
    @property
    def qsize(self) -> int:
        """获取当前队列大小"""
        return len(self._queue)
        
    @property
    def stats(self) -> QueueStats:
        """获取队列统计信息"""
        self._stats.current_size = self.qsize
        return self._stats
        
    async def put(self, item: Any, priority: int = 0, block: bool = True, timeout: Optional[float] = None) -> bool:
        """
        将具有优先级的项目放入队列
        
        Args:
            item: 要放入队列的项目
            priority: 优先级（数字越小优先级越高）
            block: 如果为True，则在空间可用时阻塞
            timeout: 阻塞时等待的最大时间
            
        Returns:
            如果项目已入队则返回True，如果被丢弃则返回False
        """
        async with self._not_full:
            if self.qsize() >= self._maxsize:
                if not block:
                    self._stats.total_dropped += 1
                    logger.warning(f"优先级队列 '{self._name}' 已满，丢弃项目")
                    return False
                    
                # 等待空间
                if timeout is not None:
                    try:
                        await asyncio.wait_for(self._not_full.wait(), timeout=timeout)
                    except asyncio.TimeoutError:
                        self._stats.total_dropped += 1
                        logger.warning(f"优先级队列 '{self._name}' 放入超时")
                        return False
                else:
                    await self._not_full.wait()
                    
            # 插入具有优先级的项目
            self._queue.append((priority, item))
            self._queue.sort(key=lambda x: x[0])  # 按优先级排序
            
            self._stats.total_enqueued += 1
            self._stats.current_size = self.qsize
            
            # 通知获取者
            self._not_empty.notify()
            return True
            
    async def get(self, block: bool = True, timeout: Optional[float] = None) -> Any:
        """
        从队列中获取最高优先级的项目
        
        Args:
            block: 如果为True，则在项目可用时阻塞
            timeout: 阻塞时等待的最大时间
            
        Returns:
            队列中的项目，如果超时则返回None
        """
        async with self._not_empty:
            if self.qsize() == 0:
                if not block:
                    return None
                    
                # 等待项目
                if timeout is not None:
                    try:
                        await asyncio.wait_for(self._not_empty.wait(), timeout=timeout)
                    except asyncio.TimeoutError:
                        return None
                else:
                    await self._not_empty.wait()
                    
            # 获取最高优先级的项目（排序列表中的第一个）
            if self._queue:
                priority, item = self._queue.pop(0)
                self._stats.total_dequeued += 1
                self._stats.current_size = self.qsize
                
                # 通知放入者
                self._not_full.notify()
                return item
                
            return None
            
    def put_nowait(self, item: Any, priority: int = 0) -> bool:
        """不阻塞地放入项目"""
        return asyncio.run_coroutine_threadsafe(self.put(item, priority, block=False), asyncio.get_event_loop()).result()
        
    def get_nowait(self) -> Any:
        """不阻塞地获取项目"""
        return asyncio.run_coroutine_threadsafe(self.get(block=False), asyncio.get_event_loop()).result()


# 队列工厂函数
def create_queue(maxsize: int = 1000, name: str = "Queue", priority: bool = False) -> Union[BoundedAsyncQueue, PriorityBoundedQueue]:
    """
    创建有界队列
    
    Args:
        maxsize: 队列最大大小
        name: 用于日志记录的队列名称
        priority: 是否创建优先级队列
        
    Returns:
        有界队列实例
    """
    if priority:
        return PriorityBoundedQueue(maxsize=maxsize, name=name)
    else:
        return BoundedAsyncQueue(maxsize=maxsize, name=name)