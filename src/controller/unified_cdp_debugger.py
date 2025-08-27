import asyncio
import logging
import re
import time
from asyncio import Queue, Future
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

from playwright.async_api import Page, CDPSession, Browser


class UnifiedCDPDebugger:
    """
    统一的CDP调试器
    """

    def __init__(self, output_q: Queue, config: dict, network_data_q: Queue = None, js_hook_events_q: Queue = None):
        self.output_q = output_q
        self.network_data_q = network_data_q
        self.js_hook_events_q = js_hook_events_q  # 用于接收JS钩子和静态分析事件
        self.config = config
        self.port = self.config['browser']['remote_debugging_port']
        self.whitelist_domains = self.config.get('scanner_scope', {}).get('whitelist_domains', [])
        self.js_reverse_config = self.config.get('js_reverse', {})
        self.js_reverse_enabled = self.js_reverse_config.get('enabled', False)
        self.logger = logging.getLogger(self.__class__.__name__)

        # --- 会话与脚本管理 ---
        self.cdp_sessions: Dict[int, CDPSession] = {}
        self.parsed_scripts: Set[str] = set()
        self.script_parse_futures: Dict[str, Future] = {}

    # region 核心架构 (V2)
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

    async def _on_paused(self, event: Dict[str, Any], session: CDPSession, page: Page):
        if not self._is_in_whitelist(page.url):
            try: await session.send('Debugger.resume')
            except Exception: pass
            return

        pause_reason = event.get('reason')
        self.logger.debug(f"Debugger paused on {page.url}. Reason: {pause_reason}.")

        if pause_reason in ['EventListener', 'XHR']:
            event_name = event.get('data', {}).get('eventName') or event.get('data', {}).get('breakpointId')
            self.logger.info(f"Breakpoint '{event_name}' triggered. Stepping into the handler to find user code...")
            try:
                await session.send('Debugger.stepInto')
            except Exception as e:
                self.logger.error(f"Failed to step into for event '{event_name}': {e}. Resuming.", exc_info=True)
                try: await session.send('Debugger.resume')
                except Exception: pass
            return

        self.logger.debug(f"Now inside a function. Processing paused event...")
        asyncio.create_task(self._process_paused_event(event, session, page))

    async def _process_paused_event(self, event: Dict[str, Any], session: CDPSession, page: Page):
        try:
            code_snippet, variables, target_frame, call_stack_summary = 'Source not available', {}, None, []
            call_frames = event.get('callFrames', [])

            if call_frames:
                call_stack_summary = [frame.get('functionName', 'anonymous') for frame in call_frames[:5]]
                for frame in call_frames:
                    location = frame.get('location', {})
                    script_id = location.get('scriptId')
                    if not script_id: continue
                    if not await self._wait_for_script_parsed(script_id): continue

                    try:
                        source_response = await session.send('Debugger.getScriptSource', {'scriptId': script_id})
                        script_source = source_response.get('scriptSource', '')
                        if script_source:
                            lines = script_source.splitlines()
                            line_number = location.get('lineNumber', 0)
                            start_line = max(0, line_number - 15)
                            end_line = min(len(lines), line_number + 15)
                            snippet_lines = [f"{start_line + i + 1:4d}{'  >> ' if start_line + i == line_number else '     '}{line}" for i, line in enumerate(lines[start_line:end_line])]
                            code_snippet = "\n".join(snippet_lines)
                            target_frame = frame
                            self.logger.debug(f"Successfully got source from parsed script {script_id}.")
                            break
                    except Exception as e:
                        self.logger.warning(f"Failed to get script source (ScriptID: {script_id}): {e}")
                        continue
                
                if not target_frame: target_frame = call_frames[0]

                for scope in target_frame.get('scopeChain', []):
                    if scope.get('type') in ['local', 'closure'] and scope.get('object', {}).get('objectId'):
                        try:
                            properties_response = await session.send('Runtime.getProperties', {'objectId': scope['object']['objectId']})
                            for prop in properties_response.get('result', []):
                                if prop.get('value') and prop.get('value').get('type') not in ['function', 'undefined']:
                                    variables[prop['name']] = str(prop.get('value').get('value', ''))[:200]
                        except Exception as e:
                            self.logger.warning(f"Failed to get scope variables: {e}")

            # --- 融合功能1: 运行时加密函数识别 ---
            analysis_hints = self._runtime_crypto_analysis(call_frames)

            self.logger.info(f"Intelligence package ready (Code snippet: {len(code_snippet)} chars)")
            debug_event = {
                'type': 'debugger_paused',
                'timestamp': time.time(),
                'url': page.url,
                'trigger': event.get('data', {}).get('eventName', 'debugger_pause'),
                'function_name': target_frame.get('functionName', 'anonymous') if target_frame else 'anonymous',
                'code_snippet': code_snippet,
                'variables': variables,
                'call_stack': call_stack_summary,
                'analysis_hints': analysis_hints  # 将分析提示加入主事件
            }
            await self.output_q.put(debug_event)

        except Exception as e:
            self.logger.error(f"Error processing CDP paused event: {e}", exc_info=True)
        finally:
            try: await session.send('Debugger.resume')
            except Exception: pass

    async def run(self, browser: Browser):
        self.logger.info("Unified CDP Debugger (V3) is running...")
        try:
            context = browser.contexts[0]
            async def _handle_new_page(page: Page):
                try:
                    await page.wait_for_load_state('load', timeout=30000)
                    self.logger.info(f"New page detected: {page.url}. Setting up debugger.")
                    await self._setup_target_listeners(page)
                except Exception as e:
                    self.logger.warning(f"Error processing new page {page.url}: {e}")

            for page in context.pages:
                asyncio.create_task(_handle_new_page(page))
            context.on("page", _handle_new_page)
            self.logger.info("Debugger now monitoring all existing and new pages in the context.")
            await asyncio.Event().wait()

        except asyncio.CancelledError:
            self.logger.info("Unified CDP Debugger received stop signal.")
        finally:
            self.logger.info("Shutting down Unified CDP Debugger...")
            for session in self.cdp_sessions.values():
                try: await session.detach() 
                except Exception: pass
            self.cdp_sessions.clear()
    # endregion

    # region 融合功能 (V3)
    def _runtime_crypto_analysis(self, call_frames: List[Dict]) -> Dict[str, Any]:
        """(融合功能1) 运行时分析调用栈中是否存在加密函数"""
        if not self.js_reverse_enabled: return {}

        crypto_patterns = self.js_reverse_config.get('crypto_patterns', {}).get('function_patterns', [])
        for frame in call_frames:
            function_name = frame.get('functionName', '').lower()
            if any(pattern in function_name for pattern in crypto_patterns):
                crypto_type = self._detect_crypto_function_type(function_name)
                self.logger.info(f"Crypto function '{function_name}' detected in call stack.")
                return {
                    'crypto_function_detected': True,
                    'function_name': frame.get('functionName'),
                    'type': crypto_type
                }
        return {}

    def _detect_crypto_function_type(self, function_name: str) -> str:
        function_name = function_name.lower()
        if any(x in function_name for x in ['encrypt', 'encode']): return 'encryption'
        if any(x in function_name for x in ['decrypt', 'decode']): return 'decryption'
        if any(x in function_name for x in ['hash', 'md5', 'sha']): return 'hashing'
        if any(x in function_name for x in ['aes', 'rsa', 'des']): return 'cipher'
        if any(x in function_name for x in ['base64']): return 'encoding'
        return 'unknown'

    async def _on_script_parsed(self, event: Dict[str, Any], session: CDPSession):
        """处理脚本解析事件，并触发静态分析"""
        script_id = event.get('scriptId')
        if not script_id: return

        # V2 逻辑: 管理脚本解析状态
        self.parsed_scripts.add(script_id)
        if script_id in self.script_parse_futures:
            if not self.script_parse_futures[script_id].done():
                self.script_parse_futures[script_id].set_result(True)
            del self.script_parse_futures[script_id]

        # 融合功能2: 静态脚本扫描
        if self.js_reverse_enabled and self._is_in_whitelist(event.get('url', '')):
            try:
                source_response = await session.send('Debugger.getScriptSource', {'scriptId': script_id})
                script_source = source_response.get('scriptSource', '')
                if script_source:
                    await self._static_analyze_script_source(script_id, event.get('url', ''), script_source)
            except Exception as e:
                self.logger.warning(f"Could not get source for static analysis (script: {script_id}): {e}")

    async def _static_analyze_script_source(self, script_id: str, url: str, source: str):
        """(融合功能2) 对脚本源码进行静态分析，寻找加密函数"""
        try:
            patterns = self.js_reverse_config.get('crypto_patterns', {}).get('function_patterns', [])
            found_functions = set()
            for pattern in patterns:
                regex = r'(?:function\s+|const\s+|let\s+|var\s+)(\w*' + re.escape(pattern) + r'\w*)\s*[=:(]'
                matches = re.findall(regex, source, re.IGNORECASE)
                for match in matches:
                    found_functions.add(match)

            if found_functions and self.js_hook_events_q:
                event = {
                    'type': 'static_js_analysis',
                    'script_id': script_id,
                    'url': url,
                    'found_functions': list(found_functions),
                    'timestamp': time.time()
                }
                await self.js_hook_events_q.put(event)
                self.logger.info(f"Static analysis found potential crypto functions in {url}: {list(found_functions)}")
        except Exception as e:
            self.logger.error(f"Error during static script analysis: {e}", exc_info=True)

    async def _inject_js_hooks(self, page: Page, session: CDPSession):
        """(融合功能3) 注入JS钩子脚本"""
        if not self.js_reverse_enabled: return
        try:
            if await page.evaluate('window.__aegis_js_re_hooked', False): return

            hook_script_path = 'src/tools/unified_hooks.js'
            with open(hook_script_path, 'r', encoding='utf-8') as f:
                hook_script = f.read()
            
            await page.evaluate(hook_script)
            await page.expose_function('__aegis_js_re_report__', 
                lambda event: asyncio.create_task(self._handle_js_hook_event(event, str(id(session)))))
            self.logger.info(f"Successfully injected JS hooks into {page.url}")
        except FileNotFoundError:
            self.logger.error(f"JS hook script not found: {hook_script_path}")
        except Exception as e:
            self.logger.error(f"Failed to inject JS hooks into {page.url}: {e}")

    async def _handle_js_hook_event(self, event: Dict[str, Any], session_id: str):
        if self.js_hook_events_q:
            js_event = {
                'type': 'js_hook_event',
                'session_id': session_id,
                'data': event,
                'timestamp': time.time()
            }
            await self.js_hook_events_q.put(js_event)

    async def _setup_target_listeners(self, page: Page):
        page_id = id(page)
        if page_id in self.cdp_sessions or not self._is_in_whitelist(page.url):
            return
        
        try:
            session = await page.context.new_cdp_session(page)
            self.cdp_sessions[page_id] = session
            self.logger.info(f"CDP session created for page {page.url}")

            session.on('Debugger.paused', lambda event: asyncio.create_task(self._on_paused(event, session, page)))
            session.on('Debugger.scriptParsed', lambda event: asyncio.create_task(self._on_script_parsed(event, session)))

            await session.send('Debugger.enable')
            await session.send('DOMDebugger.setEventListenerBreakpoint', {'eventName': 'click'})
            await session.send('DOMDebugger.setEventListenerBreakpoint', {'eventName': 'submit'})
            await session.send('DOMDebugger.setXHRBreakpoint', {'url': ''})
            
            # 融合功能3: 调用JS钩子注入
            await self._inject_js_hooks(page, session)

            self.logger.info(f"CDP Debugger (V3) activated on page {page.url}.")
        except Exception as e:
            self.logger.error(f"Failed to setup debugger for page {page.url}: {e}", exc_info=True)
            if page_id in self.cdp_sessions:
                del self.cdp_sessions[page_id]

    async def _wait_for_script_parsed(self, script_id: str, timeout: float = 2.0) -> bool:
        if script_id in self.parsed_scripts: return True
        future = asyncio.get_event_loop().create_future()
        self.script_parse_futures[script_id] = future
        try:
            await asyncio.wait_for(future, timeout=timeout)
            return True
        except asyncio.TimeoutError:
            self.logger.warning(f"Timeout waiting for script {script_id} to be parsed.")
            return False
        finally:
            if script_id in self.script_parse_futures: del self.script_parse_futures[script_id]
    # endregion
