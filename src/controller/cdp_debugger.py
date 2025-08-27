import asyncio
import logging
import json
import time
from asyncio import Queue
from typing import Any, Dict, Optional
from urllib.parse import urlparse
from playwright.async_api import Page, CDPSession, Browser

class CDPDebugger:
    """
    智能CDP调试器，根据页面特征动态设置断点，
    快速提取关键信息供AI分析。
    """

    def __init__(self, output_q: Queue, config: dict, playwright: Any):
        self.output_q = output_q
        self.config = config
        self.playwright = playwright
        self.port = self.config['browser']['remote_debugging_port']
        self.whitelist_domains = config.get('scanner_scope', {}).get('whitelist_domains', [])
        self.logger = logging.getLogger(self.__class__.__name__)
        self.cdp_sessions: Dict[Page, CDPSession] = {}

    def _is_in_whitelist(self, url: str) -> bool:
        """检查URL是否在白名单中"""
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

    async def _on_paused(self, event: Dict[str, Any], session: CDPSession, page_url: str):
        """处理断点暂停，提取结构化信息并放入调试队列。"""
        try:
            if not self._is_in_whitelist(page_url):
                return

            call_frames = event.get('callFrames', [])
            if not call_frames:
                return

            top_frame = call_frames[0]
            function_name = top_frame.get('functionName', 'anonymous')
            
            # 提取作用域内的变量
            variables = {}
            for scope in top_frame.get('scopeChain', []):
                if scope.get('type') in ['local', 'closure'] and scope.get('object', {}).get('objectId'):
                    properties_response = await session.send('Runtime.getProperties', {
                        'objectId': scope['object']['objectId']
                    })
                    for prop in properties_response.get('result', []):
                        if prop.get('value') and prop.get('value').get('type') not in ['function', 'undefined']:
                            variables[prop['name']] = str(prop.get('value').get('value', ''))[:150]

            # 构建结构化的调试事件
            debug_event = {
                'type': 'cdp_event',
                'timestamp': time.time(),
                'url': page_url,
                'trigger': event.get('data', {}).get('eventName', 'debugger_pause'),
                'function_name': function_name,
                'variables': variables,
                'call_stack': [frame.get('functionName', 'anonymous') for frame in call_frames[:5]] # 简化调用栈
            }
            
            self.logger.info(f"CDP断点触发: {debug_event['trigger']} on {debug_event['function_name']}")
            await self.output_q.put(debug_event)

        except Exception as e:
            self.logger.error(f"处理CDP暂停事件时出错: {e}", exc_info=True)
        finally:
            try:
                await session.send('Debugger.resume')
            except Exception:
                pass # 会话可能已关闭

    async def setup_debugger_for_page(self, page: Page):
        """为页面设置调试器"""
        if not self._is_in_whitelist(page.url):
            return

        try:
            self.logger.info(f"为白名单页面 '{page.url}' 设置CDP调试器...")
            session = await page.context.new_cdp_session(page)
            self.cdp_sessions[page] = session
            
            page_url = page.url
            session.on('Debugger.paused', lambda event: asyncio.create_task(self._on_paused(event, session, page_url)))
            await session.send('Debugger.enable')
            
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
        """运行CDP调试器"""
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