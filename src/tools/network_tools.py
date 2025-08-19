import httpx
import json
from typing import Dict, Any, Optional, List
from datetime import datetime
from playwright.async_api import Page, Request, Response
import asyncio

async def send_custom_request(
    url: str, 
    method: str, 
    headers: Optional[Dict] = None, 
    params: Optional[Dict] = None, 
    json_data: Optional[Dict] = None,
    data: Optional[Dict] = None
) -> Dict[str, Any]:
    """
    发送一个完全定制化的HTTP请求，并返回包含请求和响应的完整交互记录。
    这是AI代理的核心API测试工具。
    """
    try:
        async with httpx.AsyncClient(verify=False, http2=True, timeout=20.0) as client:
            # 准备请求数据以供记录
            request_log = {
                'method': method.upper(),
                'url': url,
                'headers': headers,
                'params': params,
                'json_data': json_data,
                'data': data
            }

            # 发送请求
            response = await client.request(
                method=method.upper(),
                url=url,
                headers=headers,
                params=params,
                json=json_data,
                data=data,
                follow_redirects=True
            )

            # 准备响应数据以供记录
            response_body_text = ""
            response_json = None
            try:
                # 尝试以JSON格式解析，如果失败则作为文本读取
                response_json = response.json()
                response_body_text = json.dumps(response_json, indent=2, ensure_ascii=False)
            except json.JSONDecodeError:
                response_body_text = response.text

            response_log = {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "body": response_body_text,
                "json": response_json
            }
            
            # 返回完整的交互记录
            return {"request_sent": request_log, "response_received": response_log}
            
    except httpx.TimeoutException:
        return {"error": "Request timed out."}
    except Exception as e:
        return {"error": f"An unexpected error occurred: {e}"}


class NetworkSniffer:
    """网络流量嗅探器，用于捕获和分析浏览器产生的网络请求"""
    
    def __init__(self):
        self.captured_requests: List[Dict[str, Any]] = []
        self.is_capturing: bool = False
        self._request_handlers = {}
        self._response_handlers = {}
        
    async def _on_request(self, request: Request):
        """处理捕获的请求"""
        if not self.is_capturing:
            return
            
        request_data = {
            "timestamp": datetime.now().isoformat(),
            "url": request.url,
            "method": request.method,
            "headers": dict(request.headers),
            "post_data": None,
            "resource_type": request.resource_type,
            "request_id": id(request)  # 用于匹配请求和响应
        }
        
        # 尝试获取POST数据
        try:
            post_data = request.post_data
            if post_data:
                # 尝试解析为JSON
                try:
                    request_data["post_data"] = json.loads(post_data)
                    request_data["post_data_type"] = "json"
                except json.JSONDecodeError:
                    request_data["post_data"] = post_data
                    request_data["post_data_type"] = "text"
        except:
            pass
            
        self.captured_requests.append({
            "type": "request",
            "data": request_data,
            "response": None  # 将在响应时填充
        })
        
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
                except:
                    pass
                    
                captured["response"] = response_data
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
        
    def get_captured_requests(self, filter_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """获取捕获的请求
        
        Args:
            filter_type: 可选的过滤类型 ('xhr', 'fetch', 'document', 'script', 'stylesheet', 'image')
        """
        if not filter_type:
            return self.captured_requests
            
        filtered = []
        for req in self.captured_requests:
            resource_type = req["data"].get("resource_type", "")
            if filter_type.lower() in resource_type.lower():
                filtered.append(req)
                
        return filtered
        
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


async def start_network_capture(page: Page) -> Dict[str, Any]:
    """开始捕获指定页面的网络流量
    
    Returns:
        包含状态信息的字典
    """
    page_id = str(id(page))
    
    if page_id not in _sniffers:
        _sniffers[page_id] = NetworkSniffer()
        
    sniffer = _sniffers[page_id]
    result = await sniffer.start_capture(page)
    
    return {
        **result,
        "message": "网络流量捕获已开始，所有后续的网络请求都将被记录"
    }
    

async def stop_network_capture(page: Page) -> Dict[str, Any]:
    """停止捕获指定页面的网络流量
    
    Returns:
        包含捕获统计信息的字典
    """
    page_id = str(id(page))
    
    if page_id not in _sniffers:
        return {
            "status": "error",
            "message": "该页面没有正在运行的网络捕获"
        }
        
    sniffer = _sniffers[page_id]
    result = await sniffer.stop_capture(page)
    
    return {
        **result,
        "message": f"网络流量捕获已停止，共捕获 {result.get('captured_count', 0)} 个请求"
    }
    

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
