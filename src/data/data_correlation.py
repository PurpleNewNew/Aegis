import asyncio
import uuid
import time
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

# 导入DataHub
from src.data.data_hub import DataHub


class SessionStatus(Enum):
    ACTIVE = "active"
    COMPLETED = "completed"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class CorrelatedData:
    """关联数据项"""
    data_type: str
    data: Dict[str, Any]
    timestamp: float
    session_id: str
    sequence_id: int


@dataclass
class AnalysisSession:
    """分析会话"""
    session_id: str
    trigger_event: Dict[str, Any]
    start_time: float
    status: SessionStatus = SessionStatus.ACTIVE
    correlated_data: List[CorrelatedData] = field(default_factory=list)
    timeout_seconds: int = 300  # 5分钟超时
    last_activity: float = field(default_factory=time.time)
    sequence_counter: int = 0
    
    def is_expired(self) -> bool:
        """检查会话是否过期"""
        return time.time() - self.last_activity > self.timeout_seconds
    
    def add_correlated_data(self, data_type: str, data: Dict[str, Any]) -> CorrelatedData:
        """添加关联数据"""
        self.sequence_counter += 1
        correlated_item = CorrelatedData(
            data_type=data_type,
            data=data,
            timestamp=time.time(),
            session_id=self.session_id,
            sequence_id=self.sequence_counter
        )
        self.correlated_data.append(correlated_item)
        self.last_activity = time.time()
        return correlated_item
    
    def get_data_by_type(self, data_type: str) -> List[CorrelatedData]:
        """获取指定类型的数据"""
        return [item for item in self.correlated_data if item.data_type == data_type]
    
    def complete(self):
        """完成会话"""
        self.status = SessionStatus.COMPLETED
        self.last_activity = time.time()
    
    def timeout(self):
        """会话超时"""
        self.status = SessionStatus.TIMEOUT


class DataCorrelationManager:
    """
    数据关联管理器 - 基于DataHub实现数据关联分析
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # 获取DataHub单例
        self.data_hub = DataHub.get_instance()
        
        # 订阅DataHub中的数据更新
        self.data_hub.subscribe('network_data', self._on_network_data_update)
        self.data_hub.subscribe('js_hook_events', self._on_js_event_update)
        self.data_hub.subscribe('cdp_events', self._on_cdp_event_update)
        
        # 活跃会话字典
        self.active_sessions: Dict[str, AnalysisSession] = {}
        
        # 已完成会话字典（用于短期缓存）
        self.completed_sessions: Dict[str, AnalysisSession] = {}
        
        # 配置参数
        self.max_active_sessions = self.config.get('max_active_sessions', 100)
        self.max_completed_sessions = self.config.get('max_completed_sessions', 1000)
        self.session_timeout = self.config.get('session_timeout', 300)
        self.cleanup_interval = self.config.get('cleanup_interval', 60)
        
        # 启动清理任务
        self.cleanup_task = asyncio.create_task(self._periodic_cleanup())
        
        # 统计信息
        self.stats = {
            'sessions_created': 0,
            'sessions_completed': 0,
            'sessions_timeout': 0,
            'data_correlated': 0
        }
        
    def _on_network_data_update(self, data: Dict[str, Any]):
        """处理网络数据更新"""
        session_id = data.get('session_id')
        if session_id and self.active_sessions.get(session_id):
            self.correlate_data(session_id, 'network_data', data)
        
    def _on_js_event_update(self, data: Dict[str, Any]):
        """处理JS事件更新"""
        session_id = data.get('session_id')
        if session_id and self.active_sessions.get(session_id):
            self.correlate_data(session_id, 'js_hook_event', data)
        
    def _on_cdp_event_update(self, data: Dict[str, Any]):
        """处理CDP事件更新"""
        session_id = data.get('session_id')
        if session_id and self.active_sessions.get(session_id):
            self.correlate_data(session_id, 'cdp_event', data)
    
    def create_session(self, trigger_event: Dict[str, Any]) -> str:
        """
        创建新的分析会话
        
        Args:
            trigger_event: 触发事件（通常是CDP调试事件）
            
        Returns:
            session_id: 会话ID
        """
        # 检查会话数量限制
        if len(self.active_sessions) >= self.max_active_sessions:
            self._cleanup_expired_sessions()
            
            # 如果清理后仍然超过限制，删除最旧的会话
            if len(self.active_sessions) >= self.max_active_sessions:
                oldest_session_id = min(self.active_sessions.keys(), 
                                      key=lambda sid: self.active_sessions[sid].start_time)
                self._remove_session(oldest_session_id)
        
        # 创建新会话
        session_id = str(uuid.uuid4())
        session = AnalysisSession(
            session_id=session_id,
            trigger_event=trigger_event,
            start_time=time.time(),
            timeout_seconds=self.session_timeout
        )
        
        self.active_sessions[session_id] = session
        self.stats['sessions_created'] += 1
        
        self.logger.info(f"创建分析会话: {session_id}, 触发事件: {trigger_event.get('trigger', 'unknown')}")
        return session_id
    
    def correlate_data(self, session_id: str, data_type: str, data: Dict[str, Any]) -> bool:
        """
        关联数据到指定会话
        
        Args:
            session_id: 会话ID
            data_type: 数据类型 ('cdp_event', 'network_data', 'js_hook_event')
            data: 数据内容
            
        Returns:
            bool: 关联成功返回True，失败返回False
        """
        session = self.active_sessions.get(session_id)
        if not session:
            self.logger.warning(f"尝试关联数据到不存在的会话: {session_id}")
            return False
        
        if session.status != SessionStatus.ACTIVE:
            self.logger.warning(f"尝试关联数据到非活跃会话: {session_id}, 状态: {session.status}")
            return False
        
        # 添加关联数据引用（不存储完整数据）
        # 只存储数据ID或关键标识，实际数据从DataHub获取
        data_ref = {
            'data_id': data.get('id', str(uuid.uuid4())),
            'data_type': data_type,
            'timestamp': data.get('timestamp', time.time())
        }
        
        correlated_item = session.add_correlated_data(data_type, data_ref)
        self.stats['data_correlated'] += 1
        
        self.logger.debug(f"数据关联成功: {session_id}, 类型: {data_type}, 序列ID: {correlated_item.sequence_id}")
        return True
    
    def get_session(self, session_id: str) -> Optional[AnalysisSession]:
        """获取会话"""
        session = self.active_sessions.get(session_id) or self.completed_sessions.get(session_id)
        return session
    
    def get_or_create_session(self, page_url: str, trigger_event: Optional[Dict[str, Any]] = None) -> str:
        """
        获取或创建会话ID
        
        Args:
            page_url: 页面URL，用于标识会话
            trigger_event: 触发事件，用于创建新会话
            
        Returns:
            str: 会话ID
        """
        # 首先尝试查找现有的活跃会话
        for session_id, session in self.active_sessions.items():
            if session.trigger_event and session.trigger_event.get('url') == page_url:
                # 如果会话未过期，返回现有会话ID
                if not session.is_expired():
                    return session_id
        
        # 如果没有找到合适的活跃会话，创建新会话
        if trigger_event is None:
            # 创建一个基本的触发事件
            trigger_event = {
                'url': page_url,
                'trigger': 'auto_created',
                'timestamp': time.time()
            }
        
        session_id = self.create_session(trigger_event)
        return session_id
        
    def get_active_session(self, session_id: str) -> Optional[AnalysisSession]:
        """获取活跃会话"""
        return self.active_sessions.get(session_id)
        
    def get_correlation_report(self, session_id: str) -> Dict[str, Any]:
        """
        生成关联分析报告
        
        Args:
            session_id: 会话ID
            
        Returns:
            Dict[str, Any]: 分析报告
        """
        session = self.get_session(session_id)
        if not session:
            self.logger.warning(f"无法找到会话: {session_id}")
            return {'error': 'session_not_found'}
        
        report = {
            'session_id': session_id,
            'status': session.status.value,
            'start_time': session.start_time,
            'correlated_data_types': {},
            'analysis_results': {}
        }
        
        # 统计关联数据类型和数量
        data_types = {}        
        for item in session.correlated_data:
            data_types[item.data_type] = data_types.get(item.data_type, 0) + 1
        report['correlated_data_types'] = data_types
        
        # 从DataHub获取完整数据进行分析
        for data_type in data_types.keys():
            data_ids = [item.data['data_id'] for item in session.correlated_data if item.data_type == data_type]
            data_items = []
            
            if data_type == 'network_data':
                data_items = self.data_hub.get_network_data_by_ids(data_ids)
            elif data_type == 'js_hook_event':
                data_items = self.data_hub.get_js_hook_events_by_ids(data_ids)
            elif data_type == 'cdp_event':
                data_items = self.data_hub.get_cdp_events_by_ids(data_ids)
            
            # 执行简单分析
            if data_items:
                report['analysis_results'][data_type] = {
                    'count': len(data_items),
                    'first_item': data_items[0],
                    'last_item': data_items[-1]
                }
        
        return report
    
    def complete_session(self, session_id: str) -> bool:
        """完成会话"""
        session = self.active_sessions.get(session_id)
        if not session:
            return False
        
        session.complete()
        
        # 移动到已完成会话
        self.completed_sessions[session_id] = session
        del self.active_sessions[session_id]
        
        # 清理过多的已完成会话
        if len(self.completed_sessions) > self.max_completed_sessions:
            oldest_keys = sorted(self.completed_sessions.keys(), 
                               key=lambda sid: self.completed_sessions[sid].start_time)
            for old_key in oldest_keys[:len(self.completed_sessions) - self.max_completed_sessions]:
                del self.completed_sessions[old_key]
        
        self.stats['sessions_completed'] += 1
        self.logger.info(f"会话完成: {session_id}")
        return True
    
    def timeout_session(self, session_id: str) -> bool:
        """会话超时"""
        session = self.active_sessions.get(session_id)
        if not session:
            return False
        
        session.timeout()
        
        # 移动到已完成会话
        self.completed_sessions[session_id] = session
        del self.active_sessions[session_id]
        
        self.stats['sessions_timeout'] += 1
        self.logger.warning(f"会话超时: {session_id}")
        return True
    
    def _remove_session(self, session_id: str):
        """移除会话"""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
        if session_id in self.completed_sessions:
            del self.completed_sessions[session_id]
    
    def _cleanup_expired_sessions(self):
        """清理过期会话"""
        expired_sessions = []
        for session_id, session in self.active_sessions.items():
            if session.is_expired():
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            self.timeout_session(session_id)
        
        if expired_sessions:
            self.logger.info(f"清理过期会话: {len(expired_sessions)} 个")
    
    async def _periodic_cleanup(self):
        """定期清理任务"""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                self._cleanup_expired_sessions()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"定期清理任务出错: {e}")
    
    def generate_analysis_context(self, session_id: str) -> Dict[str, Any]:
        """
        生成会话的分析上下文
        
        Args:
            session_id: 会话ID
            
        Returns:
            Dict: 包含会话相关数据的分析上下文
        """
        session = self.active_sessions.get(session_id)
        if not session:
            session = self.completed_sessions.get(session_id)
            
        if not session:
            self.logger.warning(f"尝试生成不存在的会话上下文: {session_id}")
            return {}
        
        # 收集所有关联的数据
        context = {
            'session_id': session_id,
            'trigger_event': session.trigger_event,
            'start_time': session.start_time,
            'duration': time.time() - session.start_time,
            'status': session.status.value,
            'data_summary': {}
        }
        
        # 按类型汇总数据
        data_types = ['cdp_event', 'network_request', 'network_response', 'js_hook_event', 'ai_analysis']
        for data_type in data_types:
            data_items = session.get_data_by_type(data_type)
            if data_items:
                context['data_summary'][data_type] = {
                    'count': len(data_items),
                    'latest': data_items[-1].data if data_items else None,
                    'all_data': [item.data for item in data_items]
                }
        
        # 获取完整的网络数据
        network_data = []
        network_items = session.get_data_by_type('network_request') + session.get_data_by_type('network_response')
        for item in network_items:
            if 'data_id' in item.data:
                # 从DataHub获取完整数据
                full_data = self.data_hub.get_data_by_id(item.data['data_id'])
                if full_data:
                    network_data.append(full_data)
        
        if network_data:
            context['network_data'] = network_data
            
        # 获取JS钩子事件
        js_events = []
        js_items = session.get_data_by_type('js_hook_event')
        for item in js_items:
            if 'data_id' in item.data:
                full_event = self.data_hub.get_data_by_id(item.data['data_id'])
                if full_event:
                    js_events.append(full_event)
                    
        if js_events:
            context['js_events'] = js_events
            
        # 获取AI分析结果
        ai_results = []
        ai_items = session.get_data_by_type('ai_analysis')
        for item in ai_items:
            if 'data_id' in item.data:
                full_analysis = self.data_hub.get_data_by_id(item.data['data_id'])
                if full_analysis:
                    ai_results.append(full_analysis)
                    
        if ai_results:
            context['ai_analysis'] = ai_results
            
        self.logger.debug(f"生成了会话 {session_id} 的分析上下文，包含 {len(context.get('data_summary', {}))} 种数据类型")
        return context
    
    def get_stats(self) -> Dict[str, Any]:
        """获取统计信息"""
        return {
            **self.stats,
            'active_sessions': len(self.active_sessions),
            'completed_sessions': len(self.completed_sessions),
            'total_correlated_data': sum(len(s.correlated_data) for s in self.active_sessions.values())
        }

    def associate_data(self, session_id: str, data_type: str, data: Dict[str, Any], page_url: str = None) -> bool:
        """
        关联数据到指定会话（兼容CDP调试器调用的方法）
        
        Args:
            session_id: 会话ID
            data_type: 数据类型
            data: 数据内容
            page_url: 页面URL（可选，用于兼容性）
            
        Returns:
            bool: 关联成功返回True，失败返回False
        """
        return self.correlate_data(session_id, data_type, data)

    def get_correlated_data(self, session_id: str, data_type: str, page_url: str = None) -> Optional[List[Dict[str, Any]]]:
        """
        获取指定会话的关联数据（兼容CDP调试器调用的方法）
        
        Args:
            session_id: 会话ID
            data_type: 数据类型
            page_url: 页面URL（可选，用于兼容性）
            
        Returns:
            Optional[List[Dict[str, Any]]]: 关联数据列表，如果没有找到返回None
        """
        session = self.get_session(session_id)
        if not session:
            return None
        
        # 获取指定类型的数据
        data_by_type = session.get_data_by_type(data_type)
        if not data_by_type:
            return None
        
        # 返回数据的实际内容
        return [item.data for item in data_by_type]

    async def shutdown(self):
        """关闭管理器"""
        if hasattr(self, 'cleanup_task'):
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        # 清理所有会话
        self.active_sessions.clear()
        self.completed_sessions.clear()
        
        self.logger.info("数据关联管理器已关闭")


# 全局实例
_correlation_manager = None


def get_correlation_manager(config: Dict[str, Any] = None) -> DataCorrelationManager:
    """获取全局数据关联管理器实例"""
    global _correlation_manager
    if _correlation_manager is None:
        _correlation_manager = DataCorrelationManager(config)
    return _correlation_manager


def reset_correlation_manager():
    """重置全局实例（主要用于测试）"""
    global _correlation_manager
    _correlation_manager = None