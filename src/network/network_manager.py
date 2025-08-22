"""网络数据管理器 - 统一处理所有网络数据"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Callable
from dataclasses import dataclass
from enum import Enum
from src.data.data_hub import get_data_hub
from src.data.data_correlation import get_correlation_manager

logger = logging.getLogger(__name__)


class NetworkEventType(Enum):
    """网络事件类型"""
    REQUEST = "request"
    RESPONSE = "response"
    ERROR = "error"


@dataclass
class NetworkEvent:
    """网络事件数据结构"""
    event_type: NetworkEventType
    url: str
    method: str
    headers: Dict[str, str]
    timestamp: float
    session_id: Optional[str] = None
    status_code: Optional[int] = None
    content: Optional[str] = None
    error: Optional[str] = None


class NetworkDataManager:
    """网络数据管理中心"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if hasattr(self, 'initialized'):
            return
            
        self.data_hub = get_data_hub()
        self.correlation_manager = get_correlation_manager()
        self.event_handlers: Dict[NetworkEventType, List[Callable]] = {
            event_type: [] for event_type in NetworkEventType
        }
        self.filter_rules = []
        self.stats = {
            'total_requests': 0,
            'filtered_requests': 0,
            'important_requests': 0
        }
        self.initialized = True
    
    def add_event_handler(self, event_type: NetworkEventType, handler: Callable):
        """添加事件处理器"""
        self.event_handlers[event_type].append(handler)
    
    def remove_event_handler(self, event_type: NetworkEventType, handler: Callable):
        """移除事件处理器"""
        if handler in self.event_handlers[event_type]:
            self.event_handlers[event_type].remove(handler)
    
    def process_network_event(self, event: NetworkEvent):
        """处理网络事件"""
        # 更新统计信息
        if event.event_type == NetworkEventType.REQUEST:
            self.stats['total_requests'] += 1
        
        # 应用过滤规则
        if self._should_filter_event(event):
            self.stats['filtered_requests'] += 1
            return
        
        # 判断是否为重要请求
        if self._is_important_event(event):
            self.stats['important_requests'] += 1
        
        # 发送到数据中心
        data_dict = {
            'event_type': event.event_type.value,
            'url': event.url,
            'method': event.method,
            'headers': event.headers,
            'timestamp': event.timestamp,
            'session_id': event.session_id,
            'status_code': event.status_code,
            'content': event.content,
            'error': event.error
        }
        # 生成数据ID
        data_id = f"network_{int(time.time() * 1000000)}"
        data_dict['id'] = data_id
        asyncio.create_task(self.data_hub.publish('network_data', data_dict))
        
        # 关联到会话
        if event.session_id:
            self.correlation_manager.correlate_data(
                event.session_id, 
                'network_request' if event.event_type == NetworkEventType.REQUEST else 'network_response',
                {
                    'data_id': data_id,
                    'url': event.url,
                    'timestamp': event.timestamp
                }
            )
        
        # 触发事件处理器
        for handler in self.event_handlers[event.event_type]:
            try:
                handler(event)
            except Exception as e:
                logger.error(f"事件处理器执行出错: {e}")
    
    def _should_filter_event(self, event: NetworkEvent) -> bool:
        """判断是否应该过滤事件"""
        # 实现过滤逻辑，参考NetworkRequestFilter类
        url = event.url.lower()
        
        # 噪音请求过滤
        noise_patterns = [
            '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico',
            'google-analytics.com', 'doubleclick.net', 'facebook.com',
            'googletagmanager.com', 'gstatic.com', 'cloudflare.com'
        ]
        
        for pattern in noise_patterns:
            if pattern in url:
                return True
        
        return False
    
    def _is_important_event(self, event: NetworkEvent) -> bool:
        """判断是否为重要事件"""
        # 实现重要性判断逻辑
        important_patterns = [
            '/api/', '/login', '/register', '/payment',
            'graphql', 'rest', 'json'
        ]
        
        url = event.url.lower()
        for pattern in important_patterns:
            if pattern in url:
                return True
        
        # 根据状态码判断
        if event.status_code and event.status_code >= 400:
            return True
            
        return False
    
    def get_stats(self) -> Dict:
        """获取统计信息"""
        return self.stats.copy()


def get_network_manager() -> NetworkDataManager:
    """获取网络数据管理器实例"""
    return NetworkDataManager()