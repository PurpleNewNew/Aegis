import asyncio
import logging
import json
import time
from asyncio import Queue
from typing import Any
from urllib.parse import urlparse
from playwright.async_api import async_playwright, Page, CDPSession

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
        self.cdp_sessions = {}

    def _is_in_whitelist(self, url: str) -> bool:
        if not url or not url.startswith(('http://', 'https://')):
            return False
        if not self.whitelist_domains:
            return False # 白名单为空，不监控任何页面
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

    async def _on_paused(self, event: dict, session: CDPSession, page_url: str):
        try:
            # 再次检查URL，确保事件来源合法
            if not self._is_in_whitelist(page_url):
                return

            call_frames = event.get('callFrames', [])
            if not call_frames:
                return

            top_frame = call_frames[0]
            function_name = top_frame.get('functionName', 'anonymous')
            scope_chain = top_frame.get('scopeChain', [])

            variables = {}
            for scope in scope_chain:
                if scope.get('type') in ['local', 'closure']:
                    properties = await session.send('Runtime.getProperties', {
                        'objectId': scope['object']['objectId']
                    })
                    for prop in properties.get('result', []):
                        if prop.get('value') and prop.get('value').get('type') not in ['function', 'undefined']:
                            variables[prop['name']] = str(prop.get('value').get('value', ''))[:100]

            trigger = event.get('data', {}).get('eventName', 'debugger')
            self.logger.info(f"CDP断点触发: {trigger} on {page_url}")
            # 此处可以将捕获到的调试信息放入队列，供特定分析任务消费
            # await self.output_q.put({...})

        except Exception as e:
            self.logger.error(f"处理暂停事件时出错: {e}")
        finally:
            # 恢复调试器执行
            try:
                await session.send('Debugger.resume')
            except Exception:
                pass  # 如果session已经关闭，忽略错误

    async def setup_debugger_for_page(self, page: Page):
        if not self._is_in_whitelist(page.url):
            self.logger.debug(f"页面 {page.url} 不在白名单内，跳过调试器设置。")
            return

        try:
            self.logger.info(f"为白名单页面 '{page.url}' 设置CDP调试器...")
            session = await page.context.new_cdp_session(page)
            self.cdp_sessions[page] = session
            
            page_url = page.url # 捕获当前URL以供回调使用
            session.on('Debugger.paused', lambda event: asyncio.create_task(self._on_paused(event, session, page_url)))
            await session.send('Debugger.enable')
            
            event_breakpoints = ['click', 'submit', 'input', 'change']
            for event_name in event_breakpoints:
                try:
                    await session.send('DOMDebugger.setEventListenerBreakpoint', {'eventName': event_name})
                except Exception as e:
                    self.logger.warning(f"设置 {event_name} 事件断点失败: {e}")
            
            self.logger.info(f"CDP调试器已在页面 {page.url} 上激活。")
        except Exception as e:
            self.logger.error(f"为页面 {page.url} 设置调试器失败: {e}")

    async def run(self):
        self.logger.info(f"CDP调试器正在尝试连接到端口 {self.port} 上的Chrome浏览器...")
        try:
            browser = await self.playwright.chromium.connect_over_cdp(f"http://localhost:{self.port}")
            self.logger.info("CDP调试器成功连接到Chrome。")
            
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
