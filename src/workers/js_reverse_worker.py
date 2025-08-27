import asyncio
import logging
import json
import hashlib
import re
import time
from typing import Dict, Any, Optional, List
from asyncio import Queue
from openai import AsyncOpenAI

from src.prompts.js_analysis_prompts import get_js_analysis_prompt, get_js_crypto_detection_prompt, get_network_crypto_analysis_prompt
from src.utils.ai_logger import log_ai_dialogue
from src.utils.unified_crypto_analyzer import UnifiedCryptoAnalyzer

class JSReverseWorker:
    """
    JavaScript逆向工程分析器
    专门处理和分析JS逆向事件，结合AI进行智能分析
    """

    def __init__(self, config: dict, debug_q: Queue, js_hook_events_q: Queue, network_data_q: Queue = None):
        self.config = config
        self.debug_q = debug_q
        self.js_hook_events_q = js_hook_events_q
        self.network_data_q = network_data_q
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # 初始化LLM客户端
        llm_config = self.config.get('llm_service', {})
        if llm_config and llm_config.get('api_config'):
            self.llm_client = AsyncOpenAI(
                base_url=llm_config['api_config'].get('base_url'), 
                api_key=llm_config['api_config'].get('api_key')
            )
        else:
            self.llm_client = None
            
        # 初始化统一的加密分析器
        self.crypto_analyzer = UnifiedCryptoAnalyzer(config)
        
        # 缓存机制
        self.analysis_cache = {}
        self.max_cache_size = 100
        
        # 正在处理的任务
        self.processing_tasks = set()
        
        # 数据关联
        self.session_data = {}  # session_id -> 相关数据
        
        self.logger.info("JS逆向分析器初始化完成。")

    async def run(self):
        """运行JS逆向分析器"""
        self.logger.info("JS逆向分析器开始运行，等待调试事件...")
        
        # 创建JS钩子事件处理任务
        js_hook_task = asyncio.create_task(self._process_js_hook_events(), name="JSHookProcessor")
        
        try:
            while True:
                try:
                    # 从调试队列获取事件
                    debug_event = await self.debug_q.get()
                    
                    # 异步处理调试事件
                    asyncio.create_task(self._process_debug_event(debug_event))
                    
                    self.debug_q.task_done()
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    self.logger.error(f"处理调试事件时发生未知错误: {e}", exc_info=True)
        finally:
            js_hook_task.cancel()
            await asyncio.gather(js_hook_task, return_exceptions=True)

    async def _process_js_hook_events(self):
        """处理JS钩子事件"""
        while True:
            try:
                event = await self.js_hook_events_q.get()
                session_id = event.get('session_id')
                
                if session_id:
                    # 将事件关联到会话
                    self._correlate_session_data(session_id, 'js_hook_event', event)
                
                self.js_hook_events_q.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"处理JS钩子事件时出错: {e}")

    def _correlate_session_data(self, session_id: str, data_type: str, data: Dict[str, Any]):
        """关联会话数据"""
        if session_id not in self.session_data:
            self.session_data[session_id] = {
                'debug_events': [],
                'js_hook_events': [],
                'network_data': [],
                'last_update': time.time()
            }
        
        # 添加数据
        if data_type == 'debug_event':
            self.session_data[session_id]['debug_events'].append(data)
        elif data_type == 'js_hook_event':
            self.session_data[session_id]['js_hook_events'].append(data)
        elif data_type == 'network_data':
            self.session_data[session_id]['network_data'].append(data)
        
        # 更新时间戳
        self.session_data[session_id]['last_update'] = time.time()

    def _get_session_context(self, session_id: str) -> Dict[str, Any]:
        """获取会话上下文数据"""
        if session_id not in self.session_data:
            return {}
        
        session = self.session_data[session_id]
        
        # 清理过期数据（5分钟前的）
        current_time = time.time()
        if current_time - session['last_update'] > 300:
            del self.session_data[session_id]
            return {}
        
        return {
            'debug_events': session['debug_events'][-10:],  # 最近10个事件
            'js_hook_events': session['js_hook_events'][-20:],  # 最近20个事件
            'network_data': session['network_data'][-10:],  # 最近10个网络请求
        }

    async def _process_debug_event(self, debug_event: Dict[str, Any]):
        """处理调试事件"""
        # 创建事件指纹，避免重复处理
        event_fingerprint = self._create_event_fingerprint(debug_event)
        if event_fingerprint in self.processing_tasks:
            self.logger.debug(f"事件 {event_fingerprint} 正在处理中，跳过重复分析")
            return
        
        self.processing_tasks.add(event_fingerprint)
        try:
            await self._analyze_js_reverse_event(debug_event)
        finally:
            self.processing_tasks.discard(event_fingerprint)

    def _create_event_fingerprint(self, debug_event: Dict[str, Any]) -> str:
        """创建事件指纹"""
        url = debug_event.get('url', '')
        function_name = debug_event.get('function_name', '')
        code_snippet = debug_event.get('code_snippet', '')
        fingerprint_data = f"{url}|{function_name}|{code_snippet[:500]}"
        return hashlib.md5(fingerprint_data.encode('utf-8')).hexdigest()

    async def _analyze_js_reverse_event(self, debug_event: Dict[str, Any]):
        """分析JS逆向事件"""
        # 1. 提取基本信息
        session_id = debug_event.get('session_id')
        url = debug_event.get('url')
        code_snippet = debug_event.get('code_snippet')
        variables = debug_event.get('variables', {})
        call_stack = debug_event.get('call_stack', [])
        
        if not session_id:
            self.logger.warning("调试事件缺少session_id，无法分析。")
            return

        self.logger.info(f"接收到来自 {url} 的JS逆向事件，准备分析... (会话: {session_id})")

        # 2. 检查代码片段有效性
        if not code_snippet or code_snippet == 'Source not available':
            self.logger.warning("事件中不包含有效代码片段，跳过AI分析。")
            return

        # 3. 检查LLM客户端
        if not self.llm_client:
            self.logger.warning("LLM客户端未初始化，跳过AI分析。")
            return

        # 4. 获取会话上下文
        session_context = self._get_session_context(session_id)
        
        # 5. 检查缓存
        code_hash = hashlib.md5(code_snippet.encode('utf-8')).hexdigest()
        if code_hash in self.analysis_cache:
            cached_result = self.analysis_cache[code_hash]
            self.logger.info(f"使用缓存的分析结果，URL: {url}")
            self._print_analysis_result(url, debug_event.get('function_name', 'anonymous'), cached_result, True)
            return

        # 6. 准备分析数据
        network_data = session_context.get('network_data', [])
        js_hook_events = session_context.get('js_hook_events', [])
        
        # 格式化变量
        formatted_variables = {}
        for name, info in variables.items():
            formatted_variables[name] = info['value']

        # 7. 调用AI分析
        prompt = get_js_re_prompt(
            code_snippet=code_snippet,
            variables=formatted_variables,
            url=url,
            network_data=network_data,
            js_hook_events=js_hook_events,
            analysis_context={
                'session_info': {
                    'session_id': session_id,
                    'duration': time.time() - session_context.get('debug_events', [{}])[0].get('timestamp', time.time()) if session_context.get('debug_events') else 0
                },
                'data_stats': {
                    'debug_events': len(session_context.get('debug_events', [])),
                    'js_hook_events': len(session_context.get('js_hook_events', [])),
                    'network_requests': len(session_context.get('network_data', []))
                },
                'timeline_summary': self._create_timeline_summary(session_context)
            },
            call_stack=[frame['functionName'] for frame in call_stack]
        )

        try:
            response_content = await self._call_llm(prompt)
            if response_content:
                # 增强分析结果（添加静态分析）
                enhanced_result = self._enhance_result_with_static_analysis(response_content, code_snippet)
                
                # 缓存结果
                if len(self.analysis_cache) >= self.max_cache_size:
                    self.analysis_cache.pop(next(iter(self.analysis_cache)))
                self.analysis_cache[code_hash] = enhanced_result
                
                # 输出结果
                self._print_analysis_result(url, debug_event.get('function_name', 'anonymous'), enhanced_result)
                
        except Exception as e:
            self.logger.error(f"调用LLM进行JS逆向分析时出错: {e}", exc_info=True)

    def _create_timeline_summary(self, session_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        """创建时间线摘要"""
        timeline = []
        
        # 添加调试事件
        for event in session_context.get('debug_events', [])[:3]:
            timeline.append({
                'type': 'debug_event',
                'function': event.get('function_name'),
                'timestamp': event.get('timestamp')
            })
        
        # 添加JS钩子事件
        for event in session_context.get('js_hook_events', [])[:3]:
            timeline.append({
                'type': 'js_hook_event',
                'function': event.get('functionName'),
                'timestamp': event.get('timestamp')
            })
        
        # 按时间排序
        timeline.sort(key=lambda x: x['timestamp'])
        
        return timeline[:5]  # 返回前5个事件

    def _enhance_result_with_static_analysis(self, response_content: str, code_snippet: str) -> str:
        """使用静态分析增强AI结果"""
        # 提取JSON结果
        json_result = self._extract_json_from_response(response_content)
        if json_result:
            # 使用加密分析器增强
            enhanced_json = self.crypto_analyzer.enhance_analysis_with_static_patterns(json_result, code_snippet)
            
            # 替换响应中的JSON部分
            return re.sub(
                r"```(?:json)?\s*({.*?})\s*```", 
                f"```json\n{json.dumps(enhanced_json, indent=2, ensure_ascii=False)}\n```",
                response_content, 
                flags=re.DOTALL
            )
        
        return response_content

    def _extract_json_from_response(self, response_content: str) -> Optional[Dict]:
        """从响应中提取JSON"""
        try:
            # 尝试查找代码块中的JSON
            json_match = re.search(r"```(?:json)?\s*({.*?})\s*```", response_content, re.DOTALL)
            if json_match:
                return json.loads(json_match.group(1))
            
            # 尝试直接解析整个响应
            return json.loads(response_content)
        except:
            return None

    def _print_analysis_result(self, url: str, function_name: str, response_content: str, from_cache: bool = False):
        """打印分析结果"""
        cache_indicator = " (来自缓存)" if from_cache else ""
        
        # 提取并打印JSON结果
        json_result = self._extract_json_from_response(response_content)
        if json_result:
            formatted_json = json.dumps(json_result, indent=2, ensure_ascii=False)
            self.logger.info(
                f"\n--- JS逆向分析结果{cache_indicator} ---\n"
                f"URL: {url}\n"
                f"触发函数: {function_name}\n"
                f"AI分析:\n{response_content}\n"
                f"结构化结果:\n{formatted_json}\n"
                f"-----------------------"
            )
        else:
            self.logger.info(
                f"\n--- JS逆向分析结果{cache_indicator} ---\n"
                f"URL: {url}\n"
                f"触发函数: {function_name}\n"
                f"AI分析:\n{response_content}\n"
                f"-----------------------"
            )

    async def _call_llm(self, prompt: str) -> Optional[str]:
        """调用LLM"""
        try:
            cfg = self.config['llm_service']['api_config']
            messages = [
                {"role": "system", "content": "你是一名顶级的JavaScript逆向工程专家，尤其擅长分析和破解前端加密逻辑。"},
                {"role": "user", "content": prompt}
            ]
            
            response = await asyncio.wait_for(
                self.llm_client.chat.completions.create(
                    model=cfg['model_name'],
                    messages=messages,
                    max_tokens=2048,
                    temperature=0.3
                ),
                timeout=cfg.get('timeout', 180)
            )
            
            content = response.choices[0].message.content
            
            # 记录AI对话
            await log_ai_dialogue(
                prompt, 
                content, 
                self.config.get('logging', {}).get('ai_dialogues_file', './logs/ai_dialogues.jsonl')
            )
            
            return content
        except asyncio.TimeoutError:
            self.logger.error("LLM调用超时。")
            return "[分析超时]"
        except Exception as e:
            self.logger.error(f"LLM调用失败: {e}")
            return f"[分析失败: {e}]"