"""网络数据处理模块"""

from .network_manager import (
    NetworkDataManager,
    get_network_manager,
    NetworkEventType,
    NetworkEvent
)

__all__ = [
    'NetworkDataManager',
    'get_network_manager',
    'NetworkEventType',
    'NetworkEvent'
]