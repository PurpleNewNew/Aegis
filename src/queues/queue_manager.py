import asyncio
import logging
import time
from typing import Dict, Any, Optional, List, Callable, TypeVar
from asyncio import Queue, QueueFull
from enum import Enum

# 定义队列类型枚举
class QueueType(Enum):
    DEBUG_EVENTS = "debug_events"
    NETWORK_DATA = "network_data"
    JS_HOOK_EVENTS = "js_hook_events"
    DEAD_LETTER = "dead_letter"

# 定义泛型类型
T = TypeVar('T')

class EnhancedQueue(Queue[T]):
    """增强型队列，添加监控和错误处理功能"""
    def __init__(self, maxsize: int = 0, name: str = "unknown"):
        super().__init__(maxsize)
        self.name = name
        self.logger = logging.getLogger(f"EnhancedQueue.{name}")
        self.metrics = {
            "total_enqueued": 0,
            "total_dequeued": 0,
            "current_size": 0,
            "peak_size": 0,
            "last_enqueue_time": 0,
            "last_dequeue_time": 0
        }
        self.error_handlers: List[Callable[[Exception, T], None]] = []

    async def put(self, item: T) -> None:
        try:
            await super().put(item)
            self._update_metrics(enqueue=True)
        except QueueFull:
            self.logger.warning(f"队列 {self.name} 已满，无法添加新项")
            raise
        except Exception as e:
            self.logger.error(f"向队列 {self.name} 添加项时出错: {e}")
            for handler in self.error_handlers:
                try:
                    handler(e, item)
                except Exception as he:
                    self.logger.error(f"队列 {self.name} 错误处理器执行失败: {he}")
            raise

    async def get(self) -> T:
        try:
            item = await super().get()
            self._update_metrics(enqueue=False)
            return item
        except Exception as e:
            self.logger.error(f"从队列 {self.name} 获取项时出错: {e}")
            raise

    def _update_metrics(self, enqueue: bool) -> None:
        """更新队列指标"""
        current_time = time.time()
        if enqueue:
            self.metrics["total_enqueued"] += 1
            self.metrics["last_enqueue_time"] = current_time
        else:
            self.metrics["total_dequeued"] += 1
            self.metrics["last_dequeue_time"] = current_time

        self.metrics["current_size"] = self.qsize()
        if self.metrics["current_size"] > self.metrics["peak_size"]:
            self.metrics["peak_size"] = self.metrics["current_size"]

    def add_error_handler(self, handler: Callable[[Exception, T], None]) -> None:
        """添加错误处理器"""
        self.error_handlers.append(handler)

    def get_metrics(self) -> Dict[str, Any]:
        """获取队列指标"""
        return self.metrics.copy()


class QueueManager:
    """队列管理器，用于管理多个队列并提供统一接口"""
    def __init__(self, config: dict):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.queues: Dict[QueueType, EnhancedQueue] = {}
        self._initialize_queues()
        self._start_monitoring()

    def _initialize_queues(self) -> None:
        """初始化所有队列"""
        queue_config = self.config.get('queues', {})

        # 创建调试事件队列
        self.queues[QueueType.DEBUG_EVENTS] = EnhancedQueue(
            maxsize=queue_config.get('debug_events', {}).get('maxsize', 1000),
            name="DEBUG_EVENTS"
        )

        # 创建网络数据队列
        self.queues[QueueType.NETWORK_DATA] = EnhancedQueue(
            maxsize=queue_config.get('network_data', {}).get('maxsize', 5000),
            name="NETWORK_DATA"
        )

        # 创建JS钩子事件队列
        self.queues[QueueType.JS_HOOK_EVENTS] = EnhancedQueue(
            maxsize=queue_config.get('js_hook_events', {}).get('maxsize', 2000),
            name="JS_HOOK_EVENTS"
        )

        # 创建死信队列
        self.queues[QueueType.DEAD_LETTER] = EnhancedQueue(
            maxsize=queue_config.get('dead_letter', {}).get('maxsize', 1000),
            name="DEAD_LETTER"
        )

        # 添加错误处理器，将处理失败的项发送到死信队列
        for queue_type in [QueueType.DEBUG_EVENTS, QueueType.NETWORK_DATA, QueueType.JS_HOOK_EVENTS]:
            self.queues[queue_type].add_error_handler(self._dead_letter_handler)

    def _dead_letter_handler(self, exception: Exception, item: Any) -> None:
        """将处理失败的项发送到死信队列"""
        try:
            dead_letter_item = {
                'original_item': item,
                'exception': str(exception),
                'timestamp': time.time()
            }
            self.queues[QueueType.DEAD_LETTER].put_nowait(dead_letter_item)
            self.logger.warning(f"项已移至死信队列: {exception}")
        except Exception as e:
            self.logger.error(f"将项移至死信队列时出错: {e}")

    def _start_monitoring(self) -> None:
        """启动队列监控"""
        if self.config.get('queues', {}).get('monitoring', {}).get('enabled', False):
            interval = self.config.get('queues', {}).get('monitoring', {}).get('interval', 60)
            asyncio.create_task(self._monitor_queues(interval))
            self.logger.info(f"队列监控已启动，间隔 {interval} 秒")

    async def _monitor_queues(self, interval: int) -> None:
        """定期监控队列状态"""
        while True:
            try:
                for queue_type, queue in self.queues.items():
                    metrics = queue.get_metrics()
                    self.logger.info(f"队列 {queue_type.value} 状态: 大小={metrics['current_size']}, 峰值={metrics['peak_size']}, \
                                     入队总数={metrics['total_enqueued']}, 出队总数={metrics['total_dequeued']}")
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                self.logger.info("队列监控任务已取消")
                break
            except Exception as e:
                self.logger.error(f"队列监控出错: {e}")
                await asyncio.sleep(interval)

    def get_queue(self, queue_type: QueueType) -> EnhancedQueue:
        """获取指定类型的队列"""
        if queue_type not in self.queues:
            raise ValueError(f"未知的队列类型: {queue_type}")
        return self.queues[queue_type]

    async def shutdown(self) -> None:
        """关闭队列管理器"""
        self.logger.info("正在关闭队列管理器...")
        # 取消监控任务（如果存在）
        # 清空队列（可选，根据需求）
        self.logger.info("队列管理器已关闭")