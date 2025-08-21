import asyncio
import logging
import json
import time
import base64
from asyncio import Queue
from typing import Any, Dict, Optional, List
from urllib.parse import urlparse
from playwright.async_api import Page, CDPSession, Browser, Request, Response

class CDPDebugger:
    """
    智能CDP调试器，根据页面特征动态设置断点，
    快速提取关键信息供AI分析。
    """

    def __init__(self, output_q: Queue, config: dict):
        self.output_q = output_q
        self.config = config
        self.port = self.config['browser']['remote_debugging_port']
        self.whitelist_domains = config.get('scanner_scope', {}).get('whitelist_domains', [])
        self.logger = logging.getLogger(self.__class__.__name__)
        self.cdp_sessions: Dict[Page, CDPSession] = {}
        # 存储网络请求数据
        self.network_data: Dict[str, List[Dict]] = {}

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

    async def _on_request(self, request: Request, page_url: str):
        """处理网络请求事件"""
        try:
            if not self._is_in_whitelist(page_url):
                return

            # 初始化页面的网络数据存储
            if page_url not in self.network_data:
                self.network_data[page_url] = []
                
            request_data = {
                'type': 'request',
                'timestamp': time.time(),
                'url': request.url,
                'method': request.method,
                'headers': dict(request.headers),
                'post_data': request.post_data,
                'resource_type': request.resource_type
            }
            
            self.network_data[page_url].append(request_data)
            self.logger.debug(f"捕获到网络请求: {request.method} {request.url}")
            
        except Exception as e:
            self.logger.error(f"处理网络请求事件时出错: {e}", exc_info=True)

    async def _on_response(self, response: Response, page_url: str):
        """处理网络响应事件"""
        try:
            if not self._is_in_whitelist(page_url):
                return

            # 查找对应的请求并添加响应信息
            if page_url in self.network_data:
                for req in self.network_data[page_url]:
                    if req['type'] == 'request' and req['url'] == response.url:
                        req['response'] = {
                            'status': response.status,
                            'headers': dict(response.headers)
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

            debug_event = {
                'type': 'cdp_event',
                'timestamp': time.time(),
                'url': page_url,
                'trigger': event.get('data', {}).get('eventName', 'debugger_pause'),
                'function_name': function_name,
                'code_snippet': code_snippet,
                'variables': variables,
                'call_stack': [frame.get('functionName', 'anonymous') for frame in call_frames[:5]],
                # 添加网络数据
                'network_data': self.network_data.get(page_url, [])
            }
            
            self.logger.info(f"CDP断点触发: {debug_event['trigger']} on {debug_event['function_name']}")
            await self.output_q.put(debug_event)

        except Exception as e:
            self.logger.error(f"处理CDP暂停事件时出错: {e}", exc_info=True)
        finally:
            try:
                await session.send('Debugger.resume')
            except Exception:
                pass

    async def setup_debugger_for_page(self, page: Page):
        if not self._is_in_whitelist(page.url):
            return

        try:
            self.logger.info(f"为白名单页面 '{page.url}' 设置CDP调试器...")
            session = await page.context.new_cdp_session(page)
            self.cdp_sessions[page] = session
            
            page_url = page.url
            
            # 设置网络监听器
            async def on_request(request):
                await self._on_request(request, page_url)
                
            async def on_response(response):
                await self._on_response(response, page_url)
                
            page.on("request", on_request)
            page.on("response", on_response)
            
            session.on('Debugger.paused', lambda event: asyncio.create_task(self._on_paused(event, session, page_url)))
            await session.send('Debugger.enable')
            
            self.logger.info(f"等待页面 {page.url} 完全加载...")
            await page.wait_for_load_state('load', timeout=30000)
            self.logger.info(f"页面 {page.url} 已完全加载，开始设置事件断点。")

            event_breakpoints = ['click', 'submit', 'input', 'change', 'keydown']
            for event_name in event_breakpoints:
                try:
                    await session.send('DOMDebugger.setEventListenerBreakpoint', {'eventName': event_name})
                except Exception as e:
                    self.logger.warning(f"设置 {event_name} 事件断点失败: {e}")
            
            self.logger.info(f"CDP调试器已在页面 {page.url} 上激活。")
        except Exception as e:
            self.logger.error(f"为页面 {page.url} 设置调试器失败: {e}")

    async def run(self, browser: Browser):
        self.logger.info("CDP调试器(CDPDebugger)正在启动并接管浏览器...")
        try:
            if not browser.is_connected():
                self.logger.error("传入的浏览器实例未连接！")
                return

            context = browser.contexts[0]

            async def setup_for_page(page):
                await self.setup_debugger_for_page(page)

            for page in context.pages:
                await setup_for_page(page)
            context.on("page", setup_for_page)

            self.logger.info("CDP调试器现在将只监控白名单页面的关键事件。")
            await asyncio.Event().wait()

        except asyncio.CancelledError:
            self.logger.info("CDP调试器收到关闭信号。")
        except Exception as e:
            self.logger.error(f"CDP调试器发生意外错误: {e}", exc_info=True)
        finally:
            self.logger.info("CDP调试器已关闭。")