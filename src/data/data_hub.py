import asyncio
import logging
import time
from asyncio import Queue
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime

class DataHub:
    """
    集中式数据枢纽，统一管理和存储从各个队列收集的数据，
    提供数据订阅、查询和分析功能。
    """

    # 单例模式实现
    _instance = None

    @classmethod
    def get_instance(cls) -> 'DataHub':
        if cls._instance is None:
            cls._instance = DataHub()
        return cls._instance

    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        # 存储不同类型的数据
        self.data_store: Dict[str, List[Dict]] = {
            'network_data': [],
            'cdp_events': [],
            'js_hook_events': [],
            'ai_analysis': []
        }
        # 数据订阅者
        self.subscribers: Dict[str, List[Callable]] = {
            'network_data': [],
            'cdp_events': [],
            'js_hook_events': [],
            'ai_analysis': []
        }
        # 数据清理配置
        self.max_data_age_seconds = 3600  # 默认保留1小时数据
        self.max_data_items = 10000  # 默认最多保留10000条数据
        # 启动数据清理任务
        self.cleanup_task = asyncio.create_task(self._periodic_cleanup())

    async def _periodic_cleanup(self):
        """定期清理过期数据"""
        while True:
            try:
                current_time = time.time()
                for data_type, data_list in self.data_store.items():
                    # 移除过期数据
                    filtered_data = [item for item in data_list
                                     if current_time - item.get('timestamp', 0) < self.max_data_age_seconds]
                    # 如果还是超过最大数量，保留最新的
                    if len(filtered_data) > self.max_data_items:
                        filtered_data = filtered_data[-self.max_data_items:]
                    # 更新数据存储
                    if len(filtered_data) < len(data_list):
                        self.data_store[data_type] = filtered_data
                        self.logger.debug(f"已清理 {data_type} 数据，移除了 {len(data_list) - len(filtered_data)} 条过期或多余数据")
            except Exception as e:
                self.logger.error(f"数据清理任务出错: {e}", exc_info=True)
            # 每10分钟执行一次清理
            await asyncio.sleep(600)

    def subscribe(self, data_type: str, callback: Callable):
        if data_type not in self.subscribers:
            self.subscribers[data_type] = []
        self.subscribers[data_type].append(callback)
        self.logger.info(f"已添加 {data_type} 数据订阅者")

    async def publish(self, data_type: str, data: Dict):
        if data_type not in self.data_store:
            self.data_store[data_type] = []
            self.subscribers[data_type] = []

        # 确保数据有时间戳
        if 'timestamp' not in data:
            data['timestamp'] = time.time()
            data['datetime'] = datetime.fromtimestamp(data['timestamp']).isoformat()

        # 存储数据
        self.data_store[data_type].append(data)

        # 通知订阅者
        for callback in self.subscribers.get(data_type, []):
            try:
                callback(data)
            except Exception as e:
                self.logger.error(f"通知订阅者时出错: {e}", exc_info=True)

    async def process_queue(self, queue: Queue, data_type: str):
        self.logger.info(f"开始处理 {data_type} 队列数据")
        while True:
            try:
                data = await queue.get()
                await self.publish(data_type, data)
                queue.task_done()
            except asyncio.CancelledError:
                self.logger.info(f"已取消 {data_type} 队列处理任务")
                break
            except Exception as e:
                self.logger.error(f"处理 {data_type} 队列数据时出错: {e}", exc_info=True)

    def query_data(self, data_type: str, **filters) -> List[Dict]:
        if data_type not in self.data_store:
            return []

        result = self.data_store[data_type]

        # 应用过滤器
        for key, value in filters.items():
            result = [item for item in result if item.get(key) == value]

        return result

    def get_recent_data(self, data_type: str, limit: int = 100) -> List[Dict]:
        if data_type not in self.data_store:
            return []
        return self.data_store[data_type][-limit:]
    
    def get_network_data_by_ids(self, ids: List[str]) -> List[Dict]:
        """
        根据ID列表获取网络数据
        
        Args:
            ids: 数据ID列表
            
        Returns:
            List[Dict]: 匹配的网络数据
        """
        if not ids:
            return []
        return [item for item in self.data_store.get('network_data', []) 
                if item.get('id') in ids]
    
    def get_js_hook_events_by_ids(self, ids: List[str]) -> List[Dict]:
        """
        根据ID列表获取JS钩子事件
        
        Args:
            ids: 数据ID列表
            
        Returns:
            List[Dict]: 匹配的JS钩子事件
        """
        if not ids:
            return []
        return [item for item in self.data_store.get('js_hook_events', []) 
                if item.get('id') in ids]
    
    def get_cdp_events_by_ids(self, ids: List[str]) -> List[Dict]:
        """
        根据ID列表获取CDP事件
        
        Args:
            ids: 数据ID列表
            
        Returns:
            List[Dict]: 匹配的CDP事件
        """
        if not ids:
            return []
        return [item for item in self.data_store.get('cdp_events', []) 
                if item.get('id') in ids]
    
    def get_ai_analysis_by_ids(self, ids: List[str]) -> List[Dict]:
        """
        根据ID列表获取AI分析结果
        
        Args:
            ids: 数据ID列表
            
        Returns:
            List[Dict]: 匹配的AI分析结果
        """
        # 注意：AI分析结果可能存储在不同的数据类型中，这里假设存储在'ai_analysis'类型中
        # 如果实际存储类型不同，需要相应修改
        if not ids:
            return []
        # 检查是否存在专门的ai_analysis存储类型
        if 'ai_analysis' in self.data_store:
            return [item for item in self.data_store.get('ai_analysis', []) 
                    if item.get('id') in ids]
        # 如果没有专门的存储类型，可能需要在其他类型中查找
        # 这里返回空列表，需要根据实际情况调整
        return []

    def clear_data(self, data_type: str = None):
        if data_type:
            if data_type in self.data_store:
                self.data_store[data_type] = []
                self.logger.info(f"已清除 {data_type} 数据")
        else:
            for key in self.data_store:
                self.data_store[key] = []
            self.logger.info("已清除所有数据")

    async def shutdown(self):
        self.cleanup_task.cancel()
        try:
            await self.cleanup_task
        except asyncio.CancelledError:
            pass
        self.logger.info("数据枢纽已关闭")

# 保留原函数以兼容可能的旧调用
_data_hub_instance = None

def get_data_hub() -> DataHub:
    global _data_hub_instance
    if _data_hub_instance is None:
        _data_hub_instance = DataHub.get_instance()
    return _data_hub_instance