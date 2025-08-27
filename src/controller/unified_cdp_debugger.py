import asyncio
import logging
import json
import time
import hashlib
from asyncio import Queue
from typing import Any, Dict, Optional, List
from urllib.parse import urlparse
from playwright.async_api import Page, CDPSession, Browser

class UnifiedCDPDebugger:
    """
    统一的CDP调试器，合并了基础调试和JS逆向功能
    避免了多个调试器之间的冲突
    """

    def __init__(self, output_q: Queue, config: dict, network_data_q: Queue = None, js_hook_events_q: Queue = None):
        self.output_q = output_q
        self.network_data_q = network_data_q
        self.js_hook_events_q = js_hook_events_q
        self.config = config
        self.port = self.config['browser']['remote_debugging_port']
        self.whitelist_domains = config.get('scanner_scope', {}).get('whitelist_domains', [])
        self.js_reverse_config = config.get('js_reverse', {})
        self.logger = logging.getLogger(self.__class__.__name__)
        self.cdp_sessions: Dict[Page, CDPSession] = {}
        self.script_sources: Dict[str, str] = {}  # 存储脚本源码
        self.pending_scripts: Dict[str, asyncio.Future] = {}  # 等待脚本解析完成的Future
        self.js_reverse_enabled = self.js_reverse_config.get('enabled', False)

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
        """处理断点暂停事件，合并基础调试和JS逆向功能"""
        try:
            if not self._is_in_whitelist(page_url):
                await session.send('Debugger.resume')
                return

            call_frames = event.get('callFrames', [])
            if not call_frames:
                await session.send('Debugger.resume')
                return

            # 获取调用栈信息
            debug_event = {
                'type': 'debugger_paused',
                'url': page_url,
                'timestamp': time.time(),
                'call_frames': [],
                'variables': {}
            }

            # 提取调用栈和变量
            for frame in call_frames[:5]:  # 限制深度
                frame_info = {
                    'function_name': frame.get('functionName', '<anonymous>'),
                    'url': frame.get('url', ''),
                    'line_number': frame.get('lineNumber', 0),
                    'column_number': frame.get('columnNumber', 0),
                    'scope_chain': []
                }

                # 提取作用域链
                for scope in frame.get('scopeChain', []):
                    if scope.get('type') in ['local', 'closure']:
                        # 获取作用域变量
                        scope_vars = await self._get_scope_variables(session, scope.get('object', {}).get('objectId'))
                        if scope_vars:
                            frame_info['scope_chain'].append(scope_vars)

                debug_event['call_frames'].append(frame_info)

            # 如果启用了JS逆向，进行深度分析
            if self.js_reverse_enabled:
                await self._deep_js_analysis(session, debug_event, call_frames)

            # 发送调试事件到队列
            await self.output_q.put(debug_event)

            # 恢复执行
            await session.send('Debugger.resume')

        except Exception as e:
            self.logger.error(f"处理断点事件失败: {e}")
            try:
                await session.send('Debugger.resume')
            except:
                pass

    async def _get_scope_variables(self, session: CDPSession, object_id: str) -> Dict[str, Any]:
        """获取作用域变量"""
        try:
            if not object_id:
                return {}

            result = await session.send('Runtime.getProperties', {
                'objectId': object_id,
                'ownProperties': True
            })

            variables = {}
            for prop in result.get('result', []):
                name = prop.get('name', '')
                value = prop.get('value', {})
                if value and not name.startswith('__'):
                    # 简化值的获取
                    if value.get('type') == 'string':
                        variables[name] = value.get('value', '')
                    elif value.get('type') == 'number':
                        variables[name] = value.get('value', 0)
                    elif value.get('type') == 'boolean':
                        variables[name] = value.get('value', False)
                    elif value.get('type') == 'object':
                        variables[name] = f"[Object {value.get('className', '')}]"
                    elif value.get('type') == 'function':
                        variables[name] = "[Function]"
                    else:
                        variables[name] = str(value.get('value', ''))

            return variables

        except Exception as e:
            self.logger.error(f"获取作用域变量失败: {e}")
            return {}

    async def _deep_js_analysis(self, session: CDPSession, debug_event: Dict[str, Any], call_frames: List[Dict]):
        """JS逆向深度分析"""
        try:
            # 检查是否是加密相关函数调用
            for frame in call_frames:
                function_name = frame.get('functionName', '').lower()
                
                # 检查是否匹配加密模式
                crypto_patterns = self.js_reverse_config.get('crypto_patterns', {})
                function_patterns = crypto_patterns.get('function_patterns', [])
                
                if any(pattern in function_name for pattern in function_patterns):
                    # 创建JS逆向分析事件
                    js_reverse_event = {
                        'type': 'js_reverse_analysis',
                        'function_name': frame.get('functionName'),
                        'url': frame.get('url', ''),
                        'line_number': frame.get('lineNumber', 0),
                        'timestamp': time.time(),
                        'analysis_result': {
                            'is_crypto_function': True,
                            'function_type': self._detect_function_type(function_name),
                            'call_stack': debug_event.get('call_frames', [])
                        }
                    }
                    
                    # 发送到JS逆向队列
                    if self.js_hook_events_q:
                        await self.js_hook_events_q.put(js_reverse_event)

        except Exception as e:
            self.logger.error(f"JS逆向分析失败: {e}")

    def _detect_function_type(self, function_name: str) -> str:
        """检测函数类型"""
        function_name = function_name.lower()
        if any(x in function_name for x in ['encrypt', 'encode']):
            return 'encryption'
        elif any(x in function_name for x in ['decrypt', 'decode']):
            return 'decryption'
        elif any(x in function_name for x in ['hash', 'md5', 'sha']):
            return 'hashing'
        elif any(x in function_name for x in ['aes', 'rsa', 'des']):
            return 'cipher'
        elif any(x in function_name for x in ['base64']):
            return 'encoding'
        return 'unknown'

    async def _on_script_parsed(self, event: Dict[str, Any], session: CDPSession):
        """处理脚本解析事件，用于JS逆向"""
        if not self.js_reverse_enabled:
            return

        try:
            script_id = event.get('scriptId')
            url = event.get('url', '')
            
            # 只关心我们感兴趣的脚本
            if not url or url.startswith('extensions::') or url.startswith('chrome://'):
                return
                
            # 检查是否是白名单域名
            if not self._is_in_whitelist(url):
                return

            # 获取脚本源码
            source = await session.send('Debugger.getScriptSource', {'scriptId': script_id})
            script_source = source.get('scriptSource', '')
            
            if script_source:
                self.script_sources[script_id] = script_source
                
                # 如果有等待这个脚本的Future，完成它
                if script_id in self.pending_scripts:
                    self.pending_scripts[script_id].set_result(script_source)
                    del self.pending_scripts[script_id]

                # 分析脚本中的加密函数
                await self._analyze_script_crypto_functions(script_id, url, script_source)

        except Exception as e:
            self.logger.error(f"处理脚本解析事件失败: {e}")

    async def _analyze_script_crypto_functions(self, script_id: str, url: str, source: str):
        """分析脚本中的加密函数"""
        try:
            crypto_patterns = self.js_reverse_config.get('crypto_patterns', {})
            function_patterns = crypto_patterns.get('function_patterns', [])
            
            # 简单的加密函数检测
            found_functions = []
            for pattern in function_patterns:
                if pattern.lower() in source.lower():
                    # 更精确的匹配
                    import re
                    # 匹配函数定义
                    regex = r'(?:function\s+|const\s+|let\s+|var\s+)(\w*' + re.escape(pattern) + r'\w*)\s*[=:(]'
                    matches = re.findall(regex, source, re.IGNORECASE)
                    found_functions.extend(matches)

            if found_functions:
                # 创建加密函数发现事件
                crypto_event = {
                    'type': 'crypto_functions_found',
                    'script_id': script_id,
                    'url': url,
                    'functions': list(set(found_functions)),  # 去重
                    'timestamp': time.time()
                }
                
                # 发送到JS逆向队列
                if self.js_hook_events_q:
                    await self.js_hook_events_q.put(crypto_event)

        except Exception as e:
            self.logger.error(f"分析脚本加密函数失败: {e}")

    async def _handle_js_hook_event(self, event: Dict[str, Any], session_id: str):
        """处理来自JavaScript钩子的事件"""
        if not self.js_reverse_enabled:
            return

        try:
            # 转发事件到JS逆向队列
            if self.js_hook_events_q:
                js_event = {
                    'type': 'js_hook_event',
                    'session_id': session_id,
                    'data': event,
                    'timestamp': time.time()
                }
                await self.js_hook_events_q.put(js_event)

        except Exception as e:
            self.logger.error(f"处理JS钩子事件失败: {e}")

    async def setup_session(self, page: Page, page_url: str):
        """为页面设置CDP会话"""
        try:
            if page in self.cdp_sessions:
                return

            # 创建CDP会话
            session = await page.context.new_cdp_session(page)
            self.cdp_sessions[page] = session

            # 启用Debugger
            await session.send('Debugger.enable')
            
            # 设置事件断点
            event_types = ['click', 'submit', 'input', 'change']
            if self.js_reverse_enabled:
                # JS逆向模式下监控更多事件
                js_events = self.js_reverse_config.get('event_monitoring', {}).get('event_types', [])
                event_types.extend([e for e in js_events if e not in event_types])
            
            for event_type in set(event_types):  # 去重
                await session.send('DOMDebugger.setEventListenerBreakpoint', {
                    'eventName': event_type
                })

            # 监听断点事件
            session.on('Debugger.paused', lambda event: asyncio.create_task(
                self._on_paused(event, session, page_url)
            ))

            # 如果启用了JS逆向，设置额外的监听器
            if self.js_reverse_enabled:
                # 监听脚本解析事件
                session.on('Debugger.scriptParsed', lambda event: asyncio.create_task(
                    self._on_script_parsed(event, session)
                ))

                # 注入JS逆向钩子
                await self._inject_js_hooks(page, session)

            self.logger.info(f"已为页面 {page_url} 设置CDP会话")

        except Exception as e:
            self.logger.error(f"设置CDP会话失败: {e}")

    async def _inject_js_hooks(self, page: Page, session: CDPSession):
        """注入JS逆向钩子脚本"""
        try:
            # 检查是否已经注入
            already_hooked = await page.evaluate('window.__aegis_js_re_hooked || false', False)
            if already_hooked:
                return

            # 读取钩子脚本
            hook_script_path = 'src/tools/unified_hooks.js'
            try:
                with open(hook_script_path, 'r', encoding='utf-8') as f:
                    hook_script = f.read()
            except FileNotFoundError:
                self.logger.error(f"JS逆向钩子脚本未找到: {hook_script_path}")
                return

            # 注入脚本
            await page.evaluate(hook_script)

            # 暴露报告函数
            await page.expose_function('__aegis_js_re_report__', lambda event: self._handle_js_hook_event(event, str(id(session))))

            self.logger.info("JS逆向钩子脚本注入成功")

        except Exception as e:
            self.logger.error(f"注入JS逆向钩子失败: {e}")

    async def cleanup_session(self, page: Page):
        """清理CDP会话"""
        try:
            if page in self.cdp_sessions:
                session = self.cdp_sessions[page]
                await session.detach()
                del self.cdp_sessions[page]
                self.logger.info(f"已清理页面 {page.url} 的CDP会话")
        except Exception as e:
            self.logger.error(f"清理CDP会话失败: {e}")

    async def run(self, browser: Browser):
        """运行统一调试器"""
        self.logger.info("统一CDP调试器已启动")
        
        # 保持运行状态
        while True:
            try:
                await asyncio.sleep(1)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"调试器运行错误: {e}")
        
        # 清理所有会话
        for page in list(self.cdp_sessions.keys()):
            await self.cleanup_session(page)
        
        self.logger.info("统一CDP调试器已停止")