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

    def __init__(self, output_q: Queue, config: dict):
        self.output_q = output_q
        self.config = config
        self.port = self.config['browser']['remote_debugging_port']
        self.whitelist_domains = config.get('scanner_scope', {}).get('whitelist_domains', [])
        self.logger = logging.getLogger(self.__class__.__name__)
        self.cdp_sessions: Dict[Page, CDPSession] = {}

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

    async def _on_paused(self, event: Dict[str, Any], session: CDPSession, page_url: str):
        """处理断点暂停，通过URL黑盒化所有非目标脚本，精确捕获业务逻辑。"""
        try:
            call_frames = event.get('callFrames', [])
            if not call_frames:
                await session.send('Debugger.resume')
                return

            # 核心逻辑：检查顶层调用栈的URL
            top_frame = call_frames[0]
            frame_url = top_frame.get('url', '')
            script_id = top_frame.get('location', {}).get('scriptId')

            # 如果URL是空的或不是HTTP/HTTPS协议，则判定为内部脚本，加入黑盒并跳过
            if not frame_url.startswith(('http://', 'https://')):
                self.logger.info(f"检测并黑盒化内部/注入脚本 (URL: '{frame_url}', ScriptID: {script_id})，恢复执行...")
                if script_id:
                    try:
                        source_response = await session.send('Debugger.getScriptSource', {'scriptId': script_id})
                        script_source = source_response.get('scriptSource', '')
                        await session.send('Debugger.setBlackboxedRanges', {
                            'scriptId': script_id,
                            'positions': [{'lineNumber': 0, 'columnNumber': 0}, {'lineNumber': len(script_source.splitlines()), 'columnNumber': 0}]
                        })
                    except Exception as e:
                        self.logger.warning(f"黑盒化脚本 {script_id} 失败: {e}")
                await session.send('Debugger.resume')
                return

            # 如果是HTTP/HTTPS脚本，则假定为目标业务逻辑，开始分析
            if not self._is_in_whitelist(page_url):
                await session.send('Debugger.resume')
                return

            function_name = top_frame.get('functionName', 'anonymous')
            location = top_frame.get('location', {})
            line_number = location.get('lineNumber', 0)

            # 提取代码片段
            source_response = await session.send('Debugger.getScriptSource', {'scriptId': script_id})
            script_source = source_response.get('scriptSource', '')
            lines = script_source.splitlines()
            start_line = max(0, line_number - 20)
            end_line = min(len(lines), line_number + 40)
            snippet_lines = lines[start_line:end_line]
            for i, line in enumerate(snippet_lines):
                current_line_num = start_line + i + 1
                marker = "  >> " if current_line_num == line_number + 1 else "     "
                snippet_lines[i] = f"{current_line_num:4d}{marker}{line}"
            code_snippet = "\n".join(snippet_lines)

            # 提取变量
            variables = {}
            for scope in top_frame.get('scopeChain', []):
                if scope.get('type') in ['local', 'closure'] and scope.get('object', {}).get('objectId'):
                    properties_response = await session.send('Runtime.getProperties', {
                        'objectId': scope['object']['objectId']
                    })
                    for prop in properties_response.get('result', []):
                        if prop.get('value') and prop.get('value').get('type') not in ['function', 'undefined']:
                            variables[prop['name']] = str(prop.get('value').get('value', ''))[:150]

            # 构建事件并发送
            debug_event = {
                'type': 'cdp_event',
                'timestamp': time.time(),
                'url': page_url,
                'trigger': event.get('data', {}).get('eventName', 'debugger_pause'),
                'function_name': function_name,
                'code_snippet': code_snippet,
                'variables': variables,
                'call_stack': [frame.get('functionName', 'anonymous') for frame in call_frames[:5]]
            }
            
            self.logger.info(f"成功捕获目标业务逻辑: {debug_event['trigger']} on {debug_event['function_name']}")
            await self.output_q.put(debug_event)
            await session.send('Debugger.resume')

        except Exception as e:
            self.logger.error(f"处理CDP暂停事件时出错: {e}", exc_info=True)
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
            session.on('Debugger.paused', lambda event: asyncio.create_task(self._on_paused(event, session, page_url)))
            await session.send('Debugger.enable')
            
            # 等待页面完全加载，确保所有脚本都已解析
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
