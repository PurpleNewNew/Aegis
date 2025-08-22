import asyncio
import logging
import json
import time
import base64
from asyncio import Queue
from typing import Any, Dict, Optional, List
from urllib.parse import urlparse
from playwright.async_api import Page, CDPSession, Browser, Request, Response

from src.data.data_correlation import get_correlation_manager
from src.network.network_manager import get_network_manager, NetworkEvent, NetworkEventType

# 常量定义
DEFAULT_MAX_NETWORK_DATA_PER_PAGE = 500
DEFAULT_REQUEST_RETRY_ATTEMPTS = 3
DEFAULT_REQUEST_RETRY_DELAY = 1000

class CDPDebugger:
    """
    (最终重构版)
    """

    def __init__(self, output_q: Queue, network_data_q: Queue, config: dict, interaction_worker=None):
        self.output_q = output_q
        self.network_data_q = network_data_q
        self.config = config
        self.port = self.config['browser']['remote_debugging_port']
        self.whitelist_domains = config.get('scanner_scope', {}).get('whitelist_domains', [])
        self.logger = logging.getLogger(self.__class__.__name__)
        self.interaction_worker = interaction_worker
        self.data_correlation = get_correlation_manager(config)
        self.cdp_sessions: Dict[int, CDPSession] = {}
        self.page_to_session_id: Dict[int, str] = {}
        self.request_retry_attempts = config.get('network', {}).get(
            'retry_attempts', DEFAULT_REQUEST_RETRY_ATTEMPTS)
        self.request_retry_delay = config.get('network', {}).get(
            'retry_delay', DEFAULT_REQUEST_RETRY_DELAY)

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

    async def _cleanup_page_data(self, page: Page):
        page_id = id(page)
        session_id = self.page_to_session_id.get(page_id)
        if session_id:
            self.logger.info(f"清理页面 {page.url} (会话: {session_id}) 的所有关联数据...")
            self.data_correlation.complete_session(session_id)
            if page_id in self.page_to_session_id:
                del self.page_to_session_id[page_id]
            if page_id in self.cdp_sessions:
                del self.cdp_sessions[page_id]

    async def _on_request(self, request: Request, page: Page):
        page_id = id(page)
        session_id = self.page_to_session_id.get(page_id)
        if not session_id or not self._is_in_whitelist(page.url):
            return
        try:
            get_network_manager().process_network_event(NetworkEvent(
                event_type=NetworkEventType.REQUEST,
                url=request.url, method=request.method, headers=dict(request.headers),
                timestamp=time.time(), session_id=session_id, content=request.post_data))
        except Exception as e:
            self.logger.error(f"处理网络请求事件时出错: {e}", exc_info=True)

    async def _on_response(self, response: Response, page: Page):
        page_id = id(page)
        session_id = self.page_to_session_id.get(page_id)
        if not session_id or not self._is_in_whitelist(page.url):
            return
        try:
            get_network_manager().process_network_event(NetworkEvent(
                event_type=NetworkEventType.RESPONSE,
                url=response.url, method=response.request.method, status_code=response.status,
                headers=dict(response.headers), timestamp=time.time(), session_id=session_id))
        except Exception as e:
            self.logger.error(f"处理网络响应事件时出错: {e}", exc_info=True)

    async def _on_paused(self, event: Dict[str, Any], session: CDPSession, page: Page):
        page_id = id(page)
        session_id = self.page_to_session_id.get(page_id)
        if not session_id or not self._is_in_whitelist(page.url):
            await session.send('Debugger.resume')
            return
        # 异步执行，避免阻塞CDP的其他事件处理
        asyncio.create_task(self._process_paused_event(event, session, page, session_id))

    async def _process_paused_event(self, event: Dict[str, Any], session: CDPSession, page: Page, session_id: str):
        try:
            # 1. 提取代码和变量
            code_snippet = 'Source not available'
            variables = {}
            target_frame = None
            call_frames = event.get('callFrames', [])
            function_name = 'anonymous'
            call_stack_summary = []

            if call_frames:
                # 准备调用栈摘要
                call_stack_summary = [frame.get('functionName', 'anonymous') for frame in call_frames[:5]]
                # 遍历调用栈查找源码
                for frame in call_frames:
                    location = frame.get('location', {})
                    script_id = location.get('scriptId')
                    if not script_id:
                        continue
                    try:
                        source_response = await session.send('Debugger.getScriptSource', {'scriptId': script_id})
                        script_source = source_response.get('scriptSource', '')
                        if script_source and not script_source.startswith('// Aegis internal'):
                            line_number = location.get('lineNumber', 0)
                            lines = script_source.splitlines()
                            start_line = max(0, line_number - 20)
                            end_line = min(len(lines), line_number + 40)
                            snippet_lines = [f"{start_line + i + 1:4d}{'  >> ' if start_line + i == line_number else '     '}{line}" for i, line in enumerate(lines[start_line:end_line])]
                            code_snippet = "\n".join(snippet_lines)
                            target_frame = frame
                            function_name = frame.get('functionName', 'anonymous')
                            self.logger.info(f"成功从调用栈第 {call_frames.index(frame)} 帧获取到源码: {function_name}")
                            break
                    except Exception:
                        continue
                
                # 如果循环结束仍未找到源码，则使用顶层帧作为目标
                if not target_frame:
                    target_frame = call_frames[0]
                    function_name = target_frame.get('functionName', 'anonymous')

                # 从目标帧提取变量
                for scope in target_frame.get('scopeChain', []):
                    if scope.get('type') in ['local', 'closure'] and scope.get('object', {}).get('objectId'):
                        properties_response = await session.send('Runtime.getProperties', {'objectId': scope['object']['objectId']})
                        for prop in properties_response.get('result', []):
                            if prop.get('value') and prop.get('value').get('type') not in ['function', 'undefined']:
                                variables[prop['name']] = str(prop.get('value').get('value', ''))[:150]

            # 2. 等待信息沉淀
            self.logger.info(f"断点已捕获，等待 {self.config.get('analysis_delay', 0.5)}秒 以整合上下文信息...")
            await asyncio.sleep(self.config.get('analysis_delay', 0.5))

            # 3. 统一打包
            full_context = self.data_correlation.generate_analysis_context(session_id)
            
            debug_event = {
                'type': 'cdp_event',
                'timestamp': time.time(),
                'url': page.url,
                'session_id': session_id,
                'trigger': event.get('data', {}).get('eventName', 'debugger_pause'),
                'function_name': function_name,
                'code_snippet': code_snippet,
                'variables': variables,
                'call_stack': call_stack_summary,
                'full_context': full_context
            }
            
            self.logger.info(f"信息整合完毕，发送完整情报包到分析器 (会话: {session_id})")
            await self.output_q.put(debug_event)

        except Exception as e:
            self.logger.error(f"处理CDP暂停事件时出错: {e}", exc_info=True)
        finally:
            try:
                await session.send('Debugger.resume')
            except Exception:
                pass

    async def setup_debugger_for_page(self, page: Page):
        page_id = id(page)
        if page_id in self.page_to_session_id or not self._is_in_whitelist(page.url):
            return
        try:
            trigger_event = {'url': page.url, 'trigger': 'page_load', 'timestamp': time.time()}
            session_id = self.data_correlation.create_session(trigger_event)
            self.page_to_session_id[page_id] = session_id
            self.logger.info(f"为页面 {page.url} 创建新会话: {session_id}")

            session = await page.context.new_cdp_session(page)
            self.cdp_sessions[page_id] = session
            
            if self.interaction_worker and hasattr(self.interaction_worker, '_inject_js_hooks'):
                await self.interaction_worker._inject_js_hooks(page, session_id)
            
            page.on("request", lambda req: asyncio.create_task(self._on_request(req, page)))
            page.on("response", lambda res: asyncio.create_task(self._on_response(res, page)))
            page.on("close", lambda: asyncio.create_task(self._cleanup_page_data(page)))
            
            session.on('Debugger.paused', lambda event: self._on_paused(event, session, page))
            await session.send('Debugger.enable')
            await page.wait_for_load_state('networkidle', timeout=30000)
            self.logger.info(f"页面 {page.url} (会话: {session_id}) 已完全加载，设置断点中...")
            await session.send('Network.enable')
            
            for event_name in ['click', 'submit', 'input', 'change', 'keydown', 'mouseover', 'focus']:
                try:
                    await session.send('DOMDebugger.setEventListenerBreakpoint', {'eventName': event_name})
                except Exception as e:
                    self.logger.warning(f"设置 {event_name} 事件断点失败: {e}")
            
            self.logger.info(f"CDP调试器已在页面 {page.url} (会话: {session_id}) 上激活。")
        except Exception as e:
            self.logger.error(f"为页面 {page.url} 设置调试器失败: {e}", exc_info=True)
            await self._cleanup_page_data(page)

    async def run(self, browser: Browser):
        self.logger.info("CDP调试器(最终版)正在启动并接管浏览器...")
        try:
            if not browser.is_connected():
                self.logger.error("浏览器实例未连接，启动失败。")
                return
            context = browser.contexts[0]
            async def _handle_new_page(page: Page):
                try:
                    await page.wait_for_load_state('load', timeout=30000)
                    self.logger.info(f"新页面 {page.url} 已加载，准备设置调试器。")
                    await self.setup_debugger_for_page(page)
                except Exception as e:
                    self.logger.error(f"处理新页面 {page.url} 时出错: {e}", exc_info=True)

            for page in context.pages:
                asyncio.create_task(self.setup_debugger_for_page(page))
            context.on("page", _handle_new_page)
            self.logger.info("CDP调试器现在将监控所有白名单页面的创建和关键事件。")
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.logger.info("CDP调试器收到关闭信号。")
        except Exception as e:
            self.logger.error(f"CDP调试器发生意外错误: {e}", exc_info=True)
        finally:
            self.logger.info("CDP调试器正在关闭...")
            for session_id in list(self.page_to_session_id.values()):
                self.data_correlation.complete_session(session_id)
            self.page_to_session_id.clear()
            self.cdp_sessions.clear()
            self.logger.info("CDP调试器已关闭并清理所有资源。")