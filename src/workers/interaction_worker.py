import asyncio
import logging
import json
import hashlib
import re
import time
from typing import Dict, Any, Optional
from asyncio import Queue
from openai import AsyncOpenAI

from src.prompts.prompt import get_js_re_prompt
from src.utils.ai_logger import log_ai_dialogue
from src.utils.crypto_analyzer import CryptoAnalyzer
from src.data.data_correlation import get_correlation_manager

class InteractionWorker:
    """
    (最终重构版)
    """

    def __init__(self, config: dict, debug_q: Queue, js_hook_events_q: Queue):
        self.config = config
        self.debug_q = debug_q
        self.js_hook_events_q = js_hook_events_q
        self.logger = logging.getLogger(self.__class__.__name__)
        
        llm_config = self.config.get('llm_service', {})
        if llm_config and llm_config.get('api_config'):
            self.llm_client = AsyncOpenAI(base_url=llm_config['api_config'].get('base_url'), api_key=llm_config['api_config'].get('api_key'))
        else:
            self.llm_client = None
            
        self.crypto_analyzer = CryptoAnalyzer()
        self.analysis_cache = {}
        self.max_cache_size = 100
        self.processing_tasks = set()
        self.js_hook_script = ""
        self.data_correlation = get_correlation_manager(config)
        self.logger.info("InteractionWorker (最终版) 初始化完成。")

    async def run(self):
        await self._load_js_hooks()
        self.logger.info("InteractionWorker (最终版) 开始运行，等待完整情报包...")
        js_hook_task = asyncio.create_task(self._process_js_hook_events(), name="JSHookProcessor")
        try:
            while True:
                try:
                    debug_event = await self.debug_q.get()
                    asyncio.create_task(self._process_debug_event(debug_event))
                    self.debug_q.task_done()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    self.logger.error(f"处理调试事件时发生未知错误: {e}", exc_info=True)
        finally:
            js_hook_task.cancel()
            await asyncio.gather(js_hook_task, return_exceptions=True)

    async def _load_js_hooks(self):
        try:
            with open('src/tools/js_hooks.js', 'r', encoding='utf-8') as f:
                self.js_hook_script = f.read()
        except Exception as e:
            self.logger.error(f"加载JS Hook脚本失败: {e}")

    async def _inject_js_hooks(self, page, session_id: str):
        if not self.js_hook_script:
            return
        try:
            await page.expose_function("__aegis_js_re_report__", lambda event: self._handle_js_hook_event(event))
            injection = f"window.__AEGIS_SESSION_ID__ = '{session_id}';\n{self.js_hook_script}"
            await page.add_init_script(injection)
        except Exception as e:
            self.logger.error(f"为页面 {page.url} 注入JS逆向钩子失败: {e}")

    def _handle_js_hook_event(self, event: Dict[str, Any]):
        try:
            session_id = event.get('sessionId') or event.get('session_id')
            if not session_id:
                url = event.get('url', '') or event.get('pageUrl', '')
                session_id = self.data_correlation.find_session_by_url(url)
                if not session_id:
                    return
            event['session_id'] = session_id
            event['timestamp'] = event.get('timestamp', time.time())
            self.js_hook_events_q.put_nowait(event)
        except Exception as e:
            self.logger.error(f"处理JS钩子事件时出错: {e}")

    async def _process_js_hook_events(self):
        while True:
            try:
                event = await self.js_hook_events_q.get()
                session_id = event.get('session_id')
                if session_id:
                    self.data_correlation.correlate_data(session_id, 'js_hook_event', event)
                self.js_hook_events_q.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"处理JS钩子事件队列时出错: {e}")

    async def _process_debug_event(self, debug_event: Dict[str, Any]):
        event_fingerprint = self._create_event_fingerprint(debug_event)
        if event_fingerprint in self.processing_tasks:
            self.logger.debug(f"事件 {event_fingerprint} 正在处理中，跳过重复分析")
            return
        self.processing_tasks.add(event_fingerprint)
        try:
            await self._analyze_js_snippet(debug_event)
        finally:
            self.processing_tasks.discard(event_fingerprint)

    def _create_event_fingerprint(self, debug_event: Dict[str, Any]) -> str:
        url = debug_event.get('url', '')
        function_name = debug_event.get('function_name', '')
        code_snippet = debug_event.get('code_snippet', '')
        fingerprint_data = f"{url}|{function_name}|{code_snippet[:500]}"
        return hashlib.md5(fingerprint_data.encode('utf-8')).hexdigest()

    async def _analyze_js_snippet(self, debug_event: Dict[str, Any]):
        # 1. 直接从事件中解包所有信息
        session_id = debug_event.get('session_id')
        url = debug_event.get('url')
        code_snippet = debug_event.get('code_snippet')
        variables = debug_event.get('variables')
        full_context = debug_event.get('full_context', {})

        if not session_id:
            self.logger.warning("调试事件缺少session_id，无法分析。")
            return

        self.logger.info(f"接收到来自 {url} 的完整情报包，准备分析... (会话: {session_id})")

        if not code_snippet or code_snippet == 'Source not available':
            self.logger.warning("情报包中不包含有效代码片段，跳过AI分析。")
            return

        if not self.llm_client:
            self.logger.warning("LLM客户端未初始化，跳过AI分析。")
            return

        # 2. 从预打包的上下文中提取网络和JS Hook数据
        network_data = full_context.get('network_data', [])
        js_hook_events = full_context.get('js_events', [])

        # 3. 检查缓存
        code_hash = hashlib.md5(code_snippet.encode('utf-8')).hexdigest()
        if code_hash in self.analysis_cache:
            cached_result = self.analysis_cache[code_hash]
            self.logger.info(f"使用缓存的分析结果，URL: {url}")
            self._print_analysis_result(url, debug_event.get('function_name', 'anonymous'), cached_result, True)
            return

        # 4. 调用AI
        prompt = get_js_re_prompt(code_snippet, variables, url, network_data, js_hook_events, full_context)
        try:
            response_content = await self._call_llm(prompt)
            if response_content:
                enhanced_result = self._enhance_result_with_static_analysis(response_content, code_snippet)
                if len(self.analysis_cache) >= self.max_cache_size:
                    self.analysis_cache.pop(next(iter(self.analysis_cache)))
                self.analysis_cache[code_hash] = enhanced_result
                
                analysis_result_data = {
                    'type': 'ai_analysis', 'timestamp': time.time(), 'url': url,
                    'function_name': debug_event.get('function_name', 'anonymous'),
                    'result': enhanced_result, 'session_id': session_id
                }
                self.data_correlation.correlate_data(session_id, 'ai_analysis', analysis_result_data)
                self._print_analysis_result(url, debug_event.get('function_name', 'anonymous'), enhanced_result)
        except Exception as e:
            self.logger.error(f"调用LLM进行JS逆向分析时出错: {e}", exc_info=True)

    def _enhance_result_with_static_analysis(self, response_content: str, code_snippet: str) -> str:
        json_result = self._extract_json_from_response(response_content)
        if json_result:
            enhanced_json = self.crypto_analyzer.enhance_analysis_with_static_patterns(json_result, code_snippet)
            return re.sub(r"```(?:json)?\s*({.*?})\s*```", 
                        f"```json\n{json.dumps(enhanced_json, indent=2, ensure_ascii=False)}\n```",
                        response_content, flags=re.DOTALL)
        return response_content

    def _print_analysis_result(self, url: str, function_name: str, response_content: str, from_cache: bool = False):
        cache_indicator = " (来自缓存)" if from_cache else ""
        json_result = self._extract_json_from_response(response_content)
        if json_result:
            formatted_json = json.dumps(json_result, indent=2, ensure_ascii=False)
            self.logger.info(f"\n--- AI逆向分析结果{cache_indicator} ---\nURL: {url}\n触发函数: {function_name}\n{response_content}\n结构化结果:\n{formatted_json}\n-----------------------")
        else:
            self.logger.info(f"\n--- AI逆向分析结果{cache_indicator} ---\nURL: {url}\n触发函数: {function_name}\n{response_content}\n-----------------------")

    def _extract_json_from_response(self, response_content: str) -> Optional[Dict]:
        try:
            json_match = re.search(r"```(?:json)?\s*({.*?})\s*```", response_content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(1))
            return json.loads(response_content)
        except:
            return None

    async def _call_llm(self, prompt: str) -> Optional[str]:
        try:
            cfg = self.config['llm_service']['api_config']
            messages = [{"role": "system", "content": "你是一名顶级的JavaScript逆向工程专家，尤其擅长分析和破解前端加密逻辑。"}, {"role": "user", "content": prompt}]
            response = await asyncio.wait_for(
                self.llm_client.chat.completions.create(
                    model=cfg['model_name'], messages=messages, max_tokens=2048, temperature=0.3),
                timeout=cfg.get('timeout', 180))
            content = response.choices[0].message.content
            await log_ai_dialogue(prompt, content, self.config.get('logging', {}).get('ai_dialogues_file', './logs/ai_dialogues.jsonl'))
            return content
        except asyncio.TimeoutError:
            self.logger.error("LLM调用超时。")
            return "[分析超时]"
        except Exception as e:
            self.logger.error(f"LLM调用失败: {e}")
            return f"[分析失败: {e}]"