import json
import re
from typing import Dict, Any, Optional, List
from datetime import datetime
from playwright.async_api import Page, Request, Response
import asyncio
import logging

from src.data.data_correlation import get_correlation_manager
from src.network.network_manager import get_network_manager, NetworkEvent, NetworkEventType

logger = logging.getLogger(__name__)


class NetworkRequestFilter:
    """网络请求智能过滤器，用于减少噪音并识别重要请求"""
    
    def __init__(self):
        # 定义噪音URL模式（正则表达式）
        self.noise_patterns = [
            r'\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)(\?.*)?$',  # 静态资源
            r'google-analytics\.com',  # 分析服务
            r'googletagmanager\.com',   # Google标签管理器
            r'facebook\.com',           # Facebook相关
            r'twitter\.com',            # Twitter相关
            r'linkedin\.com',           # LinkedIn相关
            r'cdn\.',                   # CDN服务
            r'fonts\.',                 # 字体服务
            r'gravatar\.com',           # 头像服务
            r'wp-content\/',            # WordPress内容
            r'wp-includes\/',           # WordPress包含文件
            r'\.min\.js',              # 压缩的JS文件
            r'\.min\.css',             # 压缩的CSS文件
        ]
        
        # 定义重要URL模式（可能包含加密或敏感信息）
        self.important_patterns = [
            r'(api|rest|graphql|service)',  # API端点
            r'(auth|login|logout|session)', # 认证相关
            r'(key|token|secret|password)',  # 密钥相关
            r'(encrypt|decrypt|sign|verify)', # 加密相关
            r'(upload|download|file)',       # 文件操作
            r'(user|account|profile)',       # 用户相关
            r'(payment|order|transaction)',   # 支付相关
            r'(config|settings|preference)', # 配置相关
        ]
        
        # 重要HTTP方法
        self.important_methods = ['POST', 'PUT', 'DELETE', 'PATCH']
        
        # 重要Content-Type
        self.important_content_types = [
            'application/json',
            'application/xml',
            'text/xml',
            'text/html',
            'application/x-www-form-urlencoded',
            'multipart/form-data'
        ]
    
    def is_noise_request(self, request: Request) -> bool:
        """判断是否为噪音请求"""
        url = request.url.lower()
        
        # 检查是否匹配噪音模式
        for pattern in self.noise_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        return False
    
    def is_important_request(self, request: Request) -> bool:
        """判断是否为重要请求"""
        url = request.url.lower()
        method = request.method.upper()
        headers = dict(request.headers)
        content_type = headers.get('content-type', '').lower()
        
        # 检查HTTP方法
        if method in self.important_methods:
            return True
        
        # 检查URL模式
        for pattern in self.important_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        # 检查Content-Type
        for ct in self.important_content_types:
            if ct in content_type:
                return True
        
        # 检查是否有POST数据（通常表示重要操作）
        if request.post_data and len(str(request.post_data)) > 0:
            return True
        
        return False
    
    def get_request_priority(self, request: Request) -> int:
        """获取请求优先级（0-10，10为最高）"""
        if self.is_noise_request(request):
            return 0
        
        priority = 1  # 基础优先级
        url = request.url.lower()
        method = request.method.upper()
        headers = dict(request.headers)
        content_type = headers.get('content-type', '').lower()
        
        # 根据HTTP方法增加优先级
        if method in ['POST', 'PUT']:
            priority += 3
        elif method in ['DELETE', 'PATCH']:
            priority += 2
        
        # 根据URL模式增加优先级
        high_priority_patterns = [
            r'(key|token|secret|password)',
            r'(encrypt|decrypt|sign|verify)',
            r'(auth|login|logout)'
        ]
        
        medium_priority_patterns = [
            r'(api|rest|graphql)',
            r'(user|account)',
            r'(payment|order)'
        ]
        
        for pattern in high_priority_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                priority += 4
                break
        
        for pattern in medium_priority_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                priority += 2
                break
        
        # 根据Content-Type增加优先级
        if 'application/json' in content_type:
            priority += 2
        elif 'application/xml' in content_type or 'text/xml' in content_type:
            priority += 1
        
        # 根据POST数据增加优先级
        if request.post_data:
            post_data_str = str(request.post_data).lower()
            if any(keyword in post_data_str for keyword in ['password', 'token', 'key', 'secret']):
                priority += 3
            elif len(post_data_str) > 50:  # 有意义的POST数据
                priority += 1
        
        return min(priority, 10)  # 最大优先级为10
    
    def filter_requests(self, requests: List[Dict[str, Any]], min_priority: int = 3) -> List[Dict[str, Any]]:
        """过滤请求列表，只保留优先级大于等于min_priority的请求"""
        filtered_requests = []
        
        for req_data in requests:
            if req_data.get('type') != 'request':
                continue
                
            # 创建模拟Request对象用于优先级计算
            class MockRequest:
                def __init__(self, data):
                    self.url = data.get('url', '')
                    self.method = data.get('method', 'GET')
                    self.headers = data.get('headers', {})
                    self.post_data = data.get('post_data')
            
            mock_request = MockRequest(req_data.get('data', {}))
            priority = self.get_request_priority(mock_request)
            
            if priority >= min_priority:
                # 添加优先级信息
                req_data_copy = req_data.copy()
                req_data_copy['priority'] = priority
                filtered_requests.append(req_data_copy)
        
        # 按优先级排序
        filtered_requests.sort(key=lambda x: x.get('priority', 0), reverse=True)
        
        return filtered_requests
    
    def get_filter_statistics(self, requests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """获取过滤统计信息"""
        total_requests = len([r for r in requests if r.get('type') == 'request'])
        
        if total_requests == 0:
            return {"total": 0, "filtered": 0, "retained": 0, "retention_rate": 0}
        
        # 模拟请求对象进行统计
        class MockRequest:
            def __init__(self, data):
                self.url = data.get('url', '')
                self.method = data.get('method', 'GET')
                self.headers = data.get('headers', {})
                self.post_data = data.get('post_data')
        
        noise_count = 0
        important_count = 0
        priority_distribution = {i: 0 for i in range(11)}
        
        for req_data in requests:
            if req_data.get('type') != 'request':
                continue
                
            mock_request = MockRequest(req_data.get('data', {}))
            
            if self.is_noise_request(mock_request):
                noise_count += 1
            
            if self.is_important_request(mock_request):
                important_count += 1
            
            priority = self.get_request_priority(mock_request)
            priority_distribution[priority] += 1
        
        filtered_count = total_requests - noise_count
        retention_rate = (filtered_count / total_requests * 100) if total_requests > 0 else 0
        
        return {
            "total": total_requests,
            "noise": noise_count,
            "important": important_count,
            "filtered": filtered_count,
            "retained": filtered_count,
            "retention_rate": round(retention_rate, 2),
            "priority_distribution": priority_distribution
        }


class NetworkSniffer:
    """网络流量嗅探器，用于捕获和分析浏览器产生的网络请求"""

    def __init__(self):
        self.captured_requests: List[Dict[str, Any]] = []
        self.is_capturing = False
        self.filter = NetworkRequestFilter()
        self.enable_smart_filtering = True  # 默认启用智能过滤
        self.min_priority_threshold = 3     # 最小优先级阈值

    async def _on_request(self, request: Request):
        """处理捕获的请求"""
        if not self.is_capturing:
            return

        request_data = {
            "type": "request",
            "timestamp": datetime.now().isoformat(),
            "data": {
                "url": request.url,
                "method": request.method,
                "headers": dict(request.headers),
                "post_data": request.post_data,
                "resource_type": request.resource_type,
                "request_id": id(request)
            }
        }
    
        # 计算请求优先级
        priority = self.filter.get_request_priority(request)
        request_data["data"]["priority"] = priority
    
        # 判断是否为噪音请求
        is_noise = self.filter.is_noise_request(request)
        request_data["data"]["is_noise"] = is_noise
    
        # 判断是否为重要请求
        is_important = self.filter.is_important_request(request)
        request_data["data"]["is_important"] = is_important
    
        # 如果启用智能过滤且是噪音请求，则跳过存储
        should_store = not (self.enable_smart_filtering and is_noise)
    
        if should_store:
            self.captured_requests.append(request_data)
            
            # 使用网络数据管理器处理请求
            network_manager = get_network_manager()
            event = NetworkEvent(
                event_type=NetworkEventType.REQUEST,
                url=request.url,
                method=request.method,
                headers=dict(request.headers),
                timestamp=datetime.now().timestamp(),
                session_id=None,  # 可以根据需要添加session_id
                content=request.post_data
            )
            
            network_manager.process_network_event(event)
    
        logger.debug(f"捕获到请求: {request.method} {request.url}")

    async def _on_response(self, response: Response):
        """处理捕获的响应"""
        if not self.is_capturing:
            return

        # 查找对应的请求
        request_id = id(response.request)
        for captured in self.captured_requests:
            if captured["type"] == "request" and captured["data"].get("request_id") == request_id:
                response_data = {
                    "status": response.status,
                    "status_text": response.status_text,
                    "headers": dict(response.headers),
                    "body": None,
                    "body_type": None
                }

                # 尝试获取响应体
                try:
                    body = await response.body()
                    content_type = response.headers.get("content-type", "")

                    if "application/json" in content_type:
                        try:
                            response_data["body"] = json.loads(body.decode('utf-8'))
                            response_data["body_type"] = "json"
                        except:
                            response_data["body"] = body.decode('utf-8', errors='ignore')
                            response_data["body_type"] = "text"
                    else:
                        # 只对文本类型的响应保存内容
                        if "text" in content_type or "html" in content_type or "xml" in content_type:
                            response_data["body"] = body.decode('utf-8', errors='ignore')[:5000]  # 限制大小
                            response_data["body_type"] = "text"
                        else:
                            response_data["body_type"] = "binary"
                            response_data["body_size"] = len(body)
                except Exception as e:
                    logger.debug(f"获取响应体失败: {e}")

                captured["response"] = response_data
                
                # 使用网络数据管理器处理响应
                network_manager = get_network_manager()
                event = NetworkEvent(
                    event_type=NetworkEventType.RESPONSE,
                    url=response.url,
                    status=response.status,
                    status_text=response.status_text,
                    headers=dict(response.headers),
                    timestamp=datetime.now().timestamp(),
                    session_id=None  # 可以根据需要添加session_id
                )
                
                network_manager.process_network_event(event)
                
                break

    async def start_capture(self, page: Page):
        """开始捕获网络流量"""
        if self.is_capturing:
            return {"status": "already_capturing"}

        self.captured_requests.clear()
        self.is_capturing = True

        # 注册事件监听器
        page.on("request", self._on_request)
        page.on("response", self._on_response)

        return {
            "status": "capture_started",
            "timestamp": datetime.now().isoformat()
        }

    async def stop_capture(self, page: Page) -> Dict[str, Any]:
        """停止捕获网络流量"""
        if not self.is_capturing:
            return {"status": "not_capturing"}

        self.is_capturing = False

        # 移除事件监听器
        try:
            page.remove_listener("request", self._on_request)
            page.remove_listener("response", self._on_response)
        except:
            pass

        return {
            "status": "capture_stopped",
            "timestamp": datetime.now().isoformat(),
            "captured_count": len(self.captured_requests)
        }

    def get_captured_requests(self, filter_type: Optional[str] = None, 
                             min_priority: Optional[int] = None,
                             include_noise: bool = False) -> List[Dict[str, Any]]:
        """获取捕获的请求

        Args:
            filter_type: 可选的过滤类型 ('xhr', 'fetch', 'document', 'script', 'stylesheet', 'image')
            min_priority: 最小优先级阈值 (0-10)
            include_noise: 是否包含噪音请求
        """
        requests = self.captured_requests
        
        # 应用过滤
        if filter_type:
            requests = [req for req in requests 
                       if filter_type.lower() in req["data"].get("resource_type", "").lower()]
        
        if not include_noise:
            requests = [req for req in requests 
                       if not req["data"].get("is_noise", False)]
        
        if min_priority is not None:
            requests = [req for req in requests 
                       if req["data"].get("priority", 0) >= min_priority]
        
        # 按优先级排序
        requests.sort(key=lambda x: x["data"].get("priority", 0), reverse=True)
        
        return requests
    
    def get_filtered_requests(self, min_priority: int = 3) -> List[Dict[str, Any]]:
        """获取经过智能过滤的请求列表
        
        Args:
            min_priority: 最小优先级阈值
        
        Returns:
            过滤后的请求列表，按优先级排序
        """
        return self.get_captured_requests(min_priority=min_priority, include_noise=False)
    
    def get_filter_statistics(self) -> Dict[str, Any]:
        """获取网络请求过滤统计信息"""
        return self.filter.get_filter_statistics(self.captured_requests)
    
    def set_smart_filtering(self, enabled: bool) -> None:
        """设置是否启用智能过滤
        
        Args:
            enabled: True启用，False禁用
        """
        self.enable_smart_filtering = enabled
        logger.info(f"智能过滤已{'启用' if enabled else '禁用'}")
    
    def set_min_priority_threshold(self, threshold: int) -> None:
        """设置最小优先级阈值
        
        Args:
            threshold: 优先级阈值 (0-10)
        """
        self.min_priority_threshold = max(0, min(10, threshold))
        logger.info(f"最小优先级阈值已设置为: {self.min_priority_threshold}")
    
    def add_noise_pattern(self, pattern: str) -> None:
        """添加噪音URL模式
        
        Args:
            pattern: 正则表达式模式
        """
        self.filter.noise_patterns.append(pattern)
        logger.info(f"已添加噪音模式: {pattern}")
    
    def add_important_pattern(self, pattern: str) -> None:
        """添加重要URL模式
        
        Args:
            pattern: 正则表达式模式
        """
        self.filter.important_patterns.append(pattern)
        logger.info(f"已添加重要模式: {pattern}")
    
    def get_high_priority_requests(self, min_priority: int = 7) -> List[Dict[str, Any]]:
        """获取高优先级请求
        
        Args:
            min_priority: 最小优先级，默认为7
        
        Returns:
            高优先级请求列表
        """
        return self.get_captured_requests(min_priority=min_priority, include_noise=False)
    
    def get_important_requests(self) -> List[Dict[str, Any]]:
        """获取标记为重要的请求
        
        Returns:
            重要请求列表
        """
        return [req for req in self.captured_requests 
                if req["data"].get("is_important", False)]

    def analyze_api_calls(self) -> Dict[str, Any]:
        """分析捕获的API调用，提取关键信息"""
        api_calls = []

        for req in self.captured_requests:
            # 只分析XHR和Fetch请求
            resource_type = req["data"].get("resource_type", "")
            if resource_type not in ["xhr", "fetch"]:
                continue

            api_info = {
                "url": req["data"]["url"],
                "method": req["data"]["method"],
                "has_post_data": req["data"]["post_data"] is not None,
                "post_data": req["data"].get("post_data"),
                "response_status": None,
                "response_body": None,
                "potential_issues": []
            }

            # 添加响应信息
            if req.get("response"):
                api_info["response_status"] = req["response"]["status"]
                api_info["response_body"] = req["response"].get("body")

            # 分析潜在的安全问题
            url = api_info["url"].lower()

            # 检查是否可能包含敏感操作
            sensitive_keywords = ["login", "auth", "password", "token", "key", "secret", "api", "admin"]
            for keyword in sensitive_keywords:
                if keyword in url:
                    api_info["potential_issues"].append(f"URL包含敏感关键词: {keyword}")

            # 检查POST数据中的潜在问题
            if api_info["has_post_data"] and isinstance(api_info["post_data"], dict):
                for key, value in api_info["post_data"].items():
                    if "password" in key.lower() and value:
                        # 检查是否看起来像是加密的
                        if len(str(value)) < 20 or str(value).isalnum():
                            api_info["potential_issues"].append(f"密码字段'{key}'可能未加密")
                        else:
                            api_info["potential_issues"].append(f"密码字段'{key}'看起来已加密")

            # 检查密钥获取请求
            if "key" in url and api_info["method"] == "GET":
                api_info["potential_issues"].append("检测到可能的密钥获取请求")

            api_calls.append(api_info)

        return {
            "total_api_calls": len(api_calls),
            "api_calls": api_calls,
            "summary": {
                "total_requests": len(self.captured_requests),
                "xhr_fetch_requests": len(api_calls),
                "has_potential_issues": any(call["potential_issues"] for call in api_calls)
            }
        }


# 全局嗅探器实例（每个页面一个）
_sniffers: Dict[str, NetworkSniffer] = {}


async def start_network_capture(page: Page, enable_smart_filtering: bool = True, 
                              min_priority_threshold: int = 3) -> Dict[str, Any]:
    """开始捕获指定页面的网络流量

    Args:
        page: Playwright页面对象
        enable_smart_filtering: 是否启用智能过滤
        min_priority_threshold: 最小优先级阈值

    Returns:
        包含状态信息的字典
    """
    page_id = str(id(page))

    if page_id not in _sniffers:
        _sniffers[page_id] = NetworkSniffer(page)

    sniffer = _sniffers[page_id]
    
    # 设置过滤参数
    sniffer.set_smart_filtering(enable_smart_filtering)
    sniffer.set_min_priority_threshold(min_priority_threshold)
    
    result = await sniffer.start_capture(page)

    return {
        **result,
        "message": f"网络流量捕获已开始，智能过滤: {'启用' if enable_smart_filtering else '禁用'}, 最小优先级阈值: {min_priority_threshold}",
        "smart_filtering_enabled": enable_smart_filtering,
        "min_priority_threshold": min_priority_threshold
    }


async def stop_network_capture(page: Page) -> Dict[str, Any]:
    """停止捕获指定页面的网络流量

    Returns:
        包含捕获统计信息和过滤统计的字典
    """
    page_id = str(id(page))

    if page_id not in _sniffers:
        return {
            "status": "error",
            "message": "该页面没有正在运行的网络捕获"
        }

    sniffer = _sniffers[page_id]
    result = await sniffer.stop_capture(page)
    
    # 获取过滤统计信息
    filter_stats = sniffer.get_filter_statistics()
    
    # 获取高优先级和重要请求
    high_priority_requests = sniffer.get_high_priority_requests()
    important_requests = sniffer.get_important_requests()

    return {
        **result,
        "message": f"网络流量捕获已停止，共捕获 {result.get('captured_count', 0)} 个请求，过滤后保留 {filter_stats.get('retained', 0)} 个请求",
        "filter_statistics": filter_stats,
        "high_priority_count": len(high_priority_requests),
        "important_requests_count": len(important_requests),
        "retention_rate": filter_stats.get("retention_rate", 0)
    }


def get_filtered_requests(page: Page, min_priority: int = 3) -> List[Dict[str, Any]]:
    """获取经过智能过滤的请求列表
    
    Args:
        page: Playwright页面对象
        min_priority: 最小优先级阈值
    
    Returns:
        过滤后的请求列表
    """
    page_id = str(id(page))
    
    if page_id not in _sniffers:
        return []
    
    sniffer = _sniffers[page_id]
    return sniffer.get_filtered_requests(min_priority)


def get_filter_statistics(page: Page) -> Dict[str, Any]:
    """获取网络请求过滤统计信息
    
    Args:
        page: Playwright页面对象
    
    Returns:
        过滤统计信息
    """
    page_id = str(id(page))
    
    if page_id not in _sniffers:
        return {"error": "没有找到该页面的嗅探器"}
    
    sniffer = _sniffers[page_id]
    return sniffer.get_filter_statistics()


def configure_smart_filtering(page: Page, enabled: bool = None, 
                             min_priority: int = None) -> Dict[str, Any]:
    """配置智能过滤参数
    
    Args:
        page: Playwright页面对象
        enabled: 是否启用智能过滤（None表示不修改）
        min_priority: 最小优先级阈值（None表示不修改）
    
    Returns:
        配置结果
    """
    page_id = str(id(page))
    
    if page_id not in _sniffers:
        return {"error": "没有找到该页面的嗅探器"}
    
    sniffer = _sniffers[page_id]
    
    changes = []
    
    if enabled is not None:
        sniffer.set_smart_filtering(enabled)
        changes.append(f"智能过滤: {'启用' if enabled else '禁用'}")
    
    if min_priority is not None:
        sniffer.set_min_priority_threshold(min_priority)
        changes.append(f"最小优先级阈值: {min_priority}")
    
    return {
        "status": "success",
        "message": f"过滤配置已更新: {', '.join(changes)}" if changes else "没有配置变更",
        "changes": changes
    }


def add_custom_filter_patterns(page: Page, noise_patterns: List[str] = None, 
                              important_patterns: List[str] = None) -> Dict[str, Any]:
    """添加自定义过滤模式
    
    Args:
        page: Playwright页面对象
        noise_patterns: 噪音URL模式列表
        important_patterns: 重要URL模式列表
    
    Returns:
        添加结果
    """
    page_id = str(id(page))
    
    if page_id not in _sniffers:
        return {"error": "没有找到该页面的嗅探器"}
    
    sniffer = _sniffers[page_id]
    
    added_patterns = []
    
    if noise_patterns:
        for pattern in noise_patterns:
            sniffer.add_noise_pattern(pattern)
            added_patterns.append(f"噪音模式: {pattern}")
    
    if important_patterns:
        for pattern in important_patterns:
            sniffer.add_important_pattern(pattern)
            added_patterns.append(f"重要模式: {pattern}")
    
    return {
        "status": "success",
        "message": f"已添加 {len(added_patterns)} 个过滤模式",
        "added_patterns": added_patterns
    }


def get_high_priority_requests(page: Page, min_priority: int = 7) -> List[Dict[str, Any]]:
    """获取高优先级请求
    
    Args:
        page: Playwright页面对象
        min_priority: 最小优先级
    
    Returns:
        高优先级请求列表
    """
    page_id = str(id(page))
    
    if page_id not in _sniffers:
        return []
    
    sniffer = _sniffers[page_id]
    return sniffer.get_high_priority_requests(min_priority)


def get_important_requests(page: Page) -> List[Dict[str, Any]]:
    """获取标记为重要的请求
    
    Args:
        page: Playwright页面对象
    
    Returns:
        重要请求列表
    """
    page_id = str(id(page))
    
    if page_id not in _sniffers:
        return []
    
    sniffer = _sniffers[page_id]
    return sniffer.get_important_requests()


def get_captured_requests(page: Page, filter_type: Optional[str] = None) -> Dict[str, Any]:
    """获取捕获的网络请求

    Args:
        page: 页面对象
        filter_type: 可选的过滤类型 ('xhr', 'fetch', 'document', 'script', 'stylesheet', 'image')

    Returns:
        包含捕获请求的字典
    """
    page_id = str(id(page))

    if page_id not in _sniffers:
        return {
            "status": "error",
            "message": "该页面没有网络捕获数据",
            "requests": []
        }

    sniffer = _sniffers[page_id]
    requests = sniffer.get_captured_requests(filter_type)

    return {
        "status": "success",
        "total_captured": len(requests),
        "filter_type": filter_type or "all",
        "requests": requests
    }


def analyze_captured_traffic(page: Page) -> Dict[str, Any]:
    """分析捕获的网络流量，提取关键信息和潜在问题

    Returns:
        包含分析结果的字典
    """
    page_id = str(id(page))

    if page_id not in _sniffers:
        return {
            "status": "error",
            "message": "该页面没有网络捕获数据"
        }

    sniffer = _sniffers[page_id]
    analysis = sniffer.analyze_api_calls()

    return {
        "status": "success",
        "analysis": analysis,
        "message": f"分析了 {analysis['summary']['xhr_fetch_requests']} 个API调用"
    }