import asyncio
import logging
import json
import time
import hashlib
from asyncio import Queue
from typing import Any, Dict, Optional, List
from urllib.parse import urlparse
from playwright.async_api import Page, CDPSession, Browser

class CDPJSReverseDebugger:
    """
    专门用于JavaScript逆向工程的CDP调试器
    能够智能捕获JS执行上下文、变量状态和调用栈
    """

    def __init__(self, output_q: Queue, config: dict, network_data_q: Queue = None):
        self.output_q = output_q
        self.network_data_q = network_data_q
        self.config = config
        self.port = self.config['browser']['remote_debugging_port']
        self.whitelist_domains = config.get('scanner_scope', {}).get('whitelist_domains', [])
        self.logger = logging.getLogger(self.__class__.__name__)
        self.cdp_sessions: Dict[Page, CDPSession] = {}
        self.script_sources: Dict[str, str] = {}  # 存储脚本源码
        self.pending_scripts: Dict[str, asyncio.Future] = {}  # 等待脚本解析完成的Future

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

    async def _on_script_parsed(self, event: Dict[str, Any], session: CDPSession):
        """处理脚本解析事件，获取脚本源码"""
        try:
            script_id = event.get('scriptId')
            url = event.get('url', '')
            
            # 只关心我们感兴趣的脚本
            if script_id and (url.startswith('http') or not url):
                # 获取脚本源码
                source_response = await session.send('Debugger.getScriptSource', {'scriptId': script_id})
                source = source_response.get('scriptSource', '')
                
                # 存储脚本源码
                self.script_sources[script_id] = source
                
                # 如果有等待这个脚本的Future，完成它
                if script_id in self.pending_scripts:
                    self.pending_scripts[script_id].set_result(source)
                    del self.pending_scripts[script_id]
                    
        except Exception as e:
            self.logger.error(f"处理脚本解析事件时出错: {e}")

    async def _on_paused(self, event: Dict[str, Any], session: CDPSession, page_url: str):
        """处理断点暂停，提取JS逆向所需的完整信息"""
        try:
            if not self._is_in_whitelist(page_url):
                await session.send('Debugger.resume')
                return

            pause_reason = event.get('reason', '')
            call_frames = event.get('callFrames', [])
            
            if not call_frames:
                await session.send('Debugger.resume')
                return

            # 如果是EventListener触发的，需要step into到实际函数
            if pause_reason == 'EventListener':
                await session.send('Debugger.stepInto')
                return

            # 获取顶层的调用帧
            top_frame = call_frames[0]
            function_name = top_frame.get('functionName', 'anonymous')
            script_id = top_frame.get('location', {}).get('scriptId')
            
            # 获取完整的调用栈
            call_stack = []
            for frame in call_frames[:10]:  # 限制调用栈深度
                call_stack.append({
                    'functionName': frame.get('functionName', 'anonymous'),
                    'url': frame.get('location', {}).get('url', ''),
                    'lineNumber': frame.get('location', {}).get('lineNumber', 0),
                    'columnNumber': frame.get('location', {}).get('columnNumber', 0)
                })
            
            # 提取变量
            variables = {}
            for scope in top_frame.get('scopeChain', []):
                scope_type = scope.get('type')
                if scope_type in ['local', 'closure', 'global'] and scope.get('object', {}).get('objectId'):
                    try:
                        properties_response = await session.send('Runtime.getProperties', {
                            'objectId': scope['object']['objectId'],
                            'ownProperties': True,
                            'accessorPropertiesOnly': False,
                            'generatePreview': False
                        })
                        
                        for prop in properties_response.get('result', []):
                            if not prop.get('value') or prop.get('value', {}).get('type') in ['function', 'undefined', 'symbol']:
                                continue
                            
                            prop_name = prop.get('name')
                            prop_value = prop.get('value', {})
                            prop_type = prop_value.get('type')
                            prop_value_data = prop_value.get('value')
                            
                            # 格式化变量值
                            if prop_type == 'object':
                                # 简化对象显示
                                if prop_value.get('className') == 'Array':
                                    prop_value_data = '[Array]'
                                elif prop_value.get('className') == 'Object':
                                    prop_value_data = '[Object]'
                                else:
                                    prop_value_data = f'[{prop_value.get("className", "Object")}]'
                            elif prop_type == 'string' and len(str(prop_value_data)) > 200:
                                prop_value_data = str(prop_value_data)[:200] + '...'
                            
                            variables[prop_name] = {
                                'type': prop_type,
                                'value': prop_value_data
                            }
                    except Exception as e:
                        self.logger.debug(f"提取作用域变量失败: {e}")

            # 获取代码片段
            code_snippet = ''
            if script_id:
                # 如果脚本源码还未获取，等待它
                if script_id not in self.script_sources:
                    future = asyncio.Future()
                    self.pending_scripts[script_id] = future
                    try:
                        await asyncio.wait_for(future, timeout=5.0)
                    except asyncio.TimeoutError:
                        self.logger.warning(f"获取脚本源码超时: {script_id}")
                
                # 获取代码片段
                source = self.script_sources.get(script_id, '')
                if source:
                    location = top_frame.get('location', {})
                    line_number = location.get('lineNumber', 0)
                    
                    # 获取前后30行代码
                    lines = source.split('\n')
                    start_line = max(0, line_number - 30)
                    end_line = min(len(lines), line_number + 30)
                    
                    code_lines = []
                    for i in range(start_line, end_line):
                        prefix = '>>> ' if i == line_number else '    '
                        code_lines.append(f"{prefix}{i+1:4d}: {lines[i]}")
                    
                    code_snippet = '\n'.join(code_lines)
            
            # 获取网络数据（如果有）
            network_data = []
            if self.network_data_q:
                # 这里可以从network_data_q获取相关的网络请求数据
                pass

            # 构建完整的调试事件
            debug_event = {
                'type': 'js_reverse_event',
                'timestamp': time.time(),
                'url': page_url,
                'trigger': event.get('data', {}).get('eventName', 'debugger_pause'),
                'function_name': function_name,
                'variables': variables,
                'call_stack': call_stack,
                'code_snippet': code_snippet or 'Source not available',
                'network_data': network_data,
                'pause_reason': pause_reason,
                'session_id': hashlib.md5(page_url.encode()).hexdigest()[:8]
            }
            
            self.logger.info(f"JS逆向断点触发: {debug_event['trigger']} on {debug_event['function_name']} at {page_url}")
            await self.output_q.put(debug_event)

        except Exception as e:
            self.logger.error(f"处理JS逆向暂停事件时出错: {e}", exc_info=True)
        finally:
            try:
                await session.send('Debugger.resume')
            except Exception:
                pass

    async def setup_debugger_for_page(self, page: Page):
        """为页面设置JS逆向调试器"""
        if not self._is_in_whitelist(page.url):
            return

        try:
            self.logger.info(f"为白名单页面 '{page.url}' 设置JS逆向调试器...")
            session = await page.context.new_cdp_session(page)
            self.cdp_sessions[page] = session
            
            page_url = page.url
            
            # 监听脚本解析事件
            session.on('Debugger.scriptParsed', lambda event: asyncio.create_task(self._on_script_parsed(event, session)))
            
            # 监听暂停事件
            session.on('Debugger.paused', lambda event: asyncio.create_task(self._on_paused(event, session, page_url)))
            
            # 启用调试器
            await session.send('Debugger.enable')
            
            # 设置事件断点
            event_breakpoints = ['click', 'submit', 'input', 'change', 'keydown', 'mousedown', 'mouseup', 'focus', 'blur']
            for event_name in event_breakpoints:
                try:
                    await session.send('DOMDebugger.setEventListenerBreakpoint', {'eventName': event_name})
                except Exception as e:
                    self.logger.warning(f"设置 {event_name} 事件断点失败: {e}")
            
            # 设置异常断点
            try:
                await session.send('Debugger.setPauseOnExceptions', {'state': 'uncaught'})
            except Exception as e:
                self.logger.warning(f"设置异常断点失败: {e}")
            
            self.logger.info(f"JS逆向调试器已在页面 {page.url} 上激活。")
        except Exception as e:
            self.logger.error(f"为页面 {page.url} 设置JS逆向调试器失败: {e}")

    async def inject_js_hooks(self, page: Page, session_id: str = None):
        """注入JS逆向钩子脚本"""
        try:
            # 读取钩子脚本
            with open('src/tools/unified_hooks.js', 'r', encoding='utf-8') as f:
                js_hooks_script = f.read()
            
            # 暴露回调函数
            await page.expose_function("__aegis_js_re_report__", lambda event: self._handle_js_hook_event(event, session_id))
            
            # 注入钩子脚本
            injection_script = f"window.__AEGIS_SESSION_ID__ = '{session_id or hashlib.md5(page.url.encode()).hexdigest()[:8]}';\n{js_hooks_script}"
            await page.add_init_script(injection_script)
            
            self.logger.info(f"JS逆向钩子已注入到页面: {page.url}")
        except Exception as e:
            self.logger.error(f"注入JS逆向钩子失败: {e}")

    def _handle_js_hook_event(self, event: Dict[str, Any], session_id: str = None):
        """处理JS钩子事件"""
        try:
            # 添加会话ID
            if not session_id:
                session_id = hashlib.md5(event.get('url', '').encode()).hexdigest()[:8]
            
            event['session_id'] = session_id
            event['timestamp'] = event.get('timestamp', time.time())
            
            # 将事件放入输出队列
            asyncio.create_task(self.output_q.put(event))
        except Exception as e:
            self.logger.error(f"处理JS钩子事件时出错: {e}")

    async def run(self, browser: Browser):
        """运行JS逆向调试器"""
        self.logger.info("JS逆向调试器正在启动...")
        try:
            if not browser.is_connected():
                self.logger.error("传入的浏览器实例未连接！")
                return

            context = browser.contexts[0]

            async def setup_for_page(page):
                await self.setup_debugger_for_page(page)
                await self.inject_js_hooks(page)

            # 为现有页面设置
            for page in context.pages:
                await setup_for_page(page)
            
            # 监听新页面
            context.on("page", setup_for_page)

            self.logger.info("JS逆向调试器现在将监控白名单页面的JavaScript执行。")
            await asyncio.Event().wait()

        except asyncio.CancelledError:
            self.logger.info("JS逆向调试器收到关闭信号。")
        except Exception as e:
            self.logger.error(f"JS逆向调试器发生意外错误: {e}", exc_info=True)
        finally:
            self.logger.info("JS逆向调试器已关闭。")