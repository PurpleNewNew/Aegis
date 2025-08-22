import asyncio
import logging
import json
import time
import base64
from asyncio import Queue
from typing import Any, Dict, Optional, List
from urllib.parse import urlparse
from playwright.async_api import Page, CDPSession, Browser, Request, Response
from src.queues.queue_manager import QueueType
from src.data.data_correlation import DataCorrelationManager

# 常量定义
DEFAULT_MAX_NETWORK_DATA_PER_PAGE = 500  # 默认每页最大网络数据条目
DEFAULT_REQUEST_RETRY_ATTEMPTS = 3  # 默认请求重试次数
DEFAULT_REQUEST_RETRY_DELAY = 1000  # 默认请求重试延迟(毫秒)

class CDPDebugger:
    """
    智能CDP调试器，根据页面特征动态设置断点，
    快速提取关键信息供AI分析。
    """

    def _is_in_whitelist(self, url: str) -> bool:
        if not url or not url.startswith(('http://', 'https://')):
            return False
        if not self.whitelist_domains:
            return False
        try:
            hostname = urlparse(url).hostname
            if not hostname:
                return False
            for domain in self.whitelist_domains:
                if hostname == domain or hostname.endswith(f'.{domain}'):
                    return True
            return False
        except Exception:
            return False

    async def _cleanup_page_data(self, page_url: str):
        """清理页面相关数据"""
        try:
            if page_url in self.recent_network_data:
                del self.recent_network_data[page_url]
                self.logger.info(f"已清理页面 {page_url} 的网络数据")
            
            # 清理关联的会话数据
            self.data_correlation.cleanup_session(page_url)
            self.logger.info(f"已清理页面 {page_url} 的会话数据")
            
        except Exception as e:
            self.logger.error(f"清理页面数据时出错: {e}", exc_info=True)

    async def _on_request(self, request: Request, page_url: str):
        """处理网络请求事件"""
        try:
            if not self._is_in_whitelist(page_url):
                return

            # 获取或创建会话ID
            session_id = self.data_correlation.get_or_create_session(page_url)
            
            request_data = {
                'type': 'request',
                'timestamp': time.time(),
                'request_id': id(request),  # 添加请求ID
                'url': request.url,
                'method': request.method,
                'headers': dict(request.headers),
                'post_data': request.post_data,
                'resource_type': request.resource_type,
                'page_url': page_url,
                'session_id': session_id
            }
            
            # 发送到网络数据专用队列
            await self.network_data_q.put(request_data)
            self.logger.debug(f"捕获并发送网络请求: {request.method} {request.url}")
            
            # 关联网络请求数据到会话
            self.data_correlation.associate_data(
                session_id, 'network_request', request_data, page_url
            )

            # 维护最近的网络数据用于调试事件分析
            if page_url not in self.recent_network_data:
                self.recent_network_data[page_url] = []

            if len(self.recent_network_data[page_url]) >= self.max_network_data_per_page:
                self.recent_network_data[page_url].pop(0)
                self.logger.debug(f"页面 {page_url} 的最近网络数据已达到上限，已移除最旧条目")

            self.recent_network_data[page_url].append(request_data)
            
        except Exception as e:
            self.logger.error(f"处理网络请求事件时出错: {e}", exc_info=True)

    async def _fetch_response_body_with_retry(self, response: Response) -> Optional[str]:
        """带重试机制的响应体获取"""
        for attempt in range(self.request_retry_attempts):
            try:
                return await response.text()
            except Exception as e:
                self.logger.warning(f"获取响应体失败 (尝试 {attempt+1}/{self.request_retry_attempts}): {e}")
                if attempt < self.request_retry_attempts - 1:
                    await asyncio.sleep(self.request_retry_delay / 1000)
        return None

    async def _on_response(self, response: Response, page_url: str):
        """处理网络响应事件"""
        try:
            if not self._is_in_whitelist(page_url):
                return

            # 获取或创建会话ID
            session_id = self.data_correlation.get_or_create_session(page_url)
            
            # 构建响应数据
            response_data = {
                'type': 'response',
                'timestamp': time.time(),
                'request_id': id(response.request),
                'url': response.url,
                'status': response.status,
                'headers': dict(response.headers),
                'body': await self._fetch_response_body_with_retry(response),
                'page_url': page_url,
                'session_id': session_id
            }

            # 发送到网络数据专用队列
            await self.network_data_q.put(response_data)
            self.logger.debug(f"捕获并发送网络响应: {response.status} {response.url}")
            
            # 关联网络响应数据到会话
            self.data_correlation.associate_data(
                session_id, 'network_response', response_data, page_url
            )

            # 更新最近网络数据中的响应信息
            if page_url in self.recent_network_data:
                for req in self.recent_network_data[page_url]:
                    if req['type'] == 'request' and req.get('request_id') == response_data['request_id']:
                        req['response'] = {
                            'status': response.status,
                            'headers': dict(response.headers),
                            'body': response_data['body']
                        }
                        break
                          
        except Exception as e:
            self.logger.error(f"处理网络响应事件时出错: {e}", exc_info=True)

    async def _on_paused(self, event: Dict[str, Any], session: CDPSession, page_url: str):
        """(简化版) 处理断点暂停，直接分析第一个捕获到的帧。"""
        try:
            if not self._is_in_whitelist(page_url):
                return

            call_frames = event.get('callFrames', [])
            if not call_frames:
                return

            top_frame = call_frames[0]
            function_name = top_frame.get('functionName', 'anonymous')
            location = top_frame.get('location', {})
            script_id = location.get('scriptId')
            line_number = location.get('lineNumber', 0)

            code_snippet = 'Source not available'
            if script_id:
                try:
                    source_response = await session.send('Debugger.getScriptSource', {'scriptId': script_id})
                    script_source = source_response.get('scriptSource', '')
                    if script_source:
                        lines = script_source.splitlines()
                        start_line = max(0, line_number - 20)
                        end_line = min(len(lines), line_number + 40)
                        snippet_lines = lines[start_line:end_line]
                        for i, line in enumerate(snippet_lines):
                            current_line_num = start_line + i + 1
                            marker = "  >> " if current_line_num == line_number + 1 else "     "
                            snippet_lines[i] = f"{current_line_num:4d}{marker}{line}"
                        code_snippet = "\n".join(snippet_lines)
                except Exception as e:
                    self.logger.warning(f"获取或处理脚本源码失败 (ScriptID: {script_id}): {e}")

            variables = {}
            for scope in top_frame.get('scopeChain', []):
                if scope.get('type') in ['local', 'closure'] and scope.get('object', {}).get('objectId'):
                    properties_response = await session.send('Runtime.getProperties', {
                        'objectId': scope['object']['objectId']
                    })
                    for prop in properties_response.get('result', []):
                        if prop.get('value') and prop.get('value').get('type') not in ['function', 'undefined']:
                            variables[prop['name']] = str(prop.get('value').get('value', ''))[:150]

            # 创建或获取会话ID
            session_id = self.data_correlation.get_or_create_session(page_url)
        
            # 关联网络数据
            correlated_network_data = self.data_correlation.get_correlated_data(
                session_id, 'network', page_url
            )
            
            debug_event = {
                'type': 'cdp_event',
                'timestamp': time.time(),
                'url': page_url,
                'session_id': session_id,
                'trigger': event.get('data', {}).get('eventName', 'debugger_pause'),
                'function_name': function_name,
                'code_snippet': code_snippet,
                'variables': variables,
                'call_stack': [frame.get('functionName', 'anonymous') for frame in call_frames[:5]],
                # 添加关联的网络数据
                'network_data': correlated_network_data or self.recent_network_data.get(page_url, [])
            }
            
            # 关联调试事件到会话
            self.data_correlation.associate_data(
                session_id, 'cdp_event', debug_event, page_url
            )
            
            self.logger.info(f"CDP断点触发: {debug_event['trigger']} on {debug_event['function_name']} (会话: {session_id})")
            await self.output_q.put(debug_event)

        except Exception as e:
            self.logger.error(f"处理CDP暂停事件时出错: {e}", exc_info=True)
        finally:
            try:
                await session.send('Debugger.resume')
            except Exception:
                pass

    def __init__(self, output_q: Queue, network_data_q: Queue, config: dict, interaction_worker=None):
        self.output_q = output_q
        self.network_data_q = network_data_q
        self.config = config
        self.port = self.config['browser']['remote_debugging_port']
        self.whitelist_domains = config.get('scanner_scope', {}).get('whitelist_domains', [])
        self.logger = logging.getLogger(self.__class__.__name__)
        self.cdp_sessions: Dict[Page, CDPSession] = {}
        # 存储最近的网络请求数据用于调试事件分析
        self.recent_network_data: Dict[str, List[Dict]] = {}
        self.interaction_worker = interaction_worker
        # 配置资源管理
        self.max_network_data_per_page = config.get('resource_management', {}).get(
            'max_network_data_per_page', DEFAULT_MAX_NETWORK_DATA_PER_PAGE)
        # 配置请求重试
        self.request_retry_attempts = config.get('network', {}).get(
            'retry_attempts', DEFAULT_REQUEST_RETRY_ATTEMPTS)
        self.request_retry_delay = config.get('network', {}).get(
            'retry_delay', DEFAULT_REQUEST_RETRY_DELAY)
        # 初始化数据关联管理器
        self.data_correlation = DataCorrelationManager(config)

    async def setup_debugger_for_page(self, page: Page):
        if not self._is_in_whitelist(page.url):
            return

        try:
            self.logger.info(f"为白名单页面 '{page.url}' 设置CDP调试器...")
            session = await page.context.new_cdp_session(page)
            self.cdp_sessions[page] = session
            
            page_url = page.url
            
            # 注入JS钩子
            if self.interaction_worker and hasattr(self.interaction_worker, '_inject_js_hooks'):
                await self.interaction_worker._inject_js_hooks(page)
            
            # 设置网络监听器
            async def on_request(request):
                await self._on_request(request, page_url)
                
            async def on_response(response):
                await self._on_response(response, page_url)
                
            async def on_close():
                await self._cleanup_page_data(page_url)
                if page in self.cdp_sessions:
                    del self.cdp_sessions[page]
                    self.logger.info(f"已关闭页面 {page_url} 的CDP会话")

            page.on("request", on_request)
            page.on("response", on_response)
            page.on("close", on_close)
            
            session.on('Debugger.paused', lambda event: asyncio.create_task(self._on_paused(event, session, page_url)))
            await session.send('Debugger.enable')
            
            self.logger.info(f"等待页面 {page.url} 完全加载...")
            # 增强异步加载监控：使用networkidle状态
            await page.wait_for_load_state('networkidle', timeout=30000)
            self.logger.info(f"页面 {page.url} 已完全加载(networkidle)，开始设置事件断点。")

            # 启用网络监控而不是尝试拦截特定资源类型
            try:
                await session.send('Network.enable')
                self.logger.info("网络监控已启用")
            except Exception as e:
                self.logger.warning(f"启用网络监控失败: {e}")
            
            # 设置事件断点（这部分是正确的）
            event_breakpoints = ['click', 'submit', 'input', 'change', 'keydown', 'mouseover', 'focus']
            for event_name in event_breakpoints:
                try:
                    await session.send('DOMDebugger.setEventListenerBreakpoint', {'eventName': event_name})
                except Exception as e:
                    self.logger.warning(f"设置 {event_name} 事件断点失败: {e}")

            # 移除有问题的资源类型拦截代码
            # 注意：下面的代码已被移除，因为它使用了无效的resourceType值
            # resource_types = ['script', 'xhr', 'fetch', 'websocket']
            # for resource_type in resource_types:
            #     try:
            #         await session.send('Network.setRequestInterception', {
            #             'patterns': [{
            #                 'resourceType': resource_type,
            #                 'interceptionStage': 'Request'
            #             }]
            #         })
            #     except Exception as e:
            #         self.logger.warning(f"设置 {resource_type} 资源拦截失败: {e}")
            
            self.logger.info(f"CDP调试器已在页面 {page.url} 上激活。")
        except Exception as e:
            self.logger.error(f"为页面 {page.url} 设置调试器失败: {e}")
            # 尝试清理部分资源
            await self._cleanup_page_data(page.url)

    async def _reconnect_session(self, page: Page) -> bool:
        """尝试重新连接CDP会话"""
        try:
            if page in self.cdp_sessions:
                del self.cdp_sessions[page]
            session = await page.context.new_cdp_session(page)
            self.cdp_sessions[page] = session
            await session.send('Debugger.enable')
            self.logger.info(f"已重新连接页面 {page.url} 的CDP会话")
            return True
        except Exception as e:
            self.logger.error(f"重新连接页面 {page.url} 的CDP会话失败: {e}")
            return False

    async def run(self, browser: Browser):
        self.logger.info("CDP调试器(CDPDebugger)正在启动并接管浏览器...")
        try:
            if not browser.is_connected():
                self.logger.error("传入的浏览器实例未连接！")
                # 尝试重新连接浏览器
                retry_count = 3
                for i in range(retry_count):
                    try:
                        self.logger.info(f"尝试重新连接浏览器 (尝试 {i+1}/{retry_count})...")
                        # 这里简化处理，实际项目中可能需要更复杂的重连逻辑
                        await asyncio.sleep(2)
                        if browser.is_connected():
                            self.logger.info("浏览器重新连接成功！")
                            break
                    except Exception as e:
                        self.logger.error(f"重新连接浏览器失败: {e}")
                if not browser.is_connected():
                    self.logger.error("无法重新连接浏览器，CDP调试器启动失败。")
                    return

            context = browser.contexts[0]

            async def setup_for_page(page):
                await self.setup_debugger_for_page(page)

            for page in context.pages:
                await setup_for_page(page)
            context.on("page", setup_for_page)

            # 定期检查会话状态并清理过期数据
            async def session_maintainer():
                while True:
                    try:
                        # 检查所有会话状态
                        for page, session in list(self.cdp_sessions.items()):
                            try:
                                # 发送一个简单命令测试会话是否活跃
                                await session.send('Runtime.evaluate', {'expression': '1+1'})
                            except Exception as e:
                                self.logger.warning(f"会话测试失败，尝试重新连接: {e}")
                                await self._reconnect_session(page)
                        
                        # 清理长时间未活动的网络数据（例如超过1小时）
                        current_time = time.time()
                        for page_url, data_list in list(self.recent_network_data.items()):
                            if not data_list or current_time - data_list[-1]['timestamp'] > 3600:
                                await self._cleanup_page_data(page_url)
                        
                        await asyncio.sleep(60)  # 每分钟检查一次
                    except Exception as e:
                        self.logger.error(f"会话维护任务出错: {e}")
                        await asyncio.sleep(10)  # 出错后等待10秒再尝试

            # 启动会话维护任务
            asyncio.create_task(session_maintainer())

            self.logger.info("CDP调试器现在将只监控白名单页面的关键事件。")
            await asyncio.Event().wait()

        except asyncio.CancelledError:
            self.logger.info("CDP调试器收到关闭信号。")
        except Exception as e:
            self.logger.error(f"CDP调试器发生意外错误: {e}", exc_info=True)
        finally:
            # 清理所有数据
            for page_url in list(self.recent_network_data.keys()):
                await self._cleanup_page_data(page_url)
            self.cdp_sessions.clear()
            self.logger.info("CDP调试器已关闭并清理所有资源。")