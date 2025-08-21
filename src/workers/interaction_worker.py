import asyncio
import logging
import json
import hashlib
import re
from typing import Dict, Any, Optional, List
from asyncio import Queue
from openai import AsyncOpenAI

from src.prompts.prompt import get_js_re_prompt
from src.utils.ai_logger import log_ai_dialogue
from src.utils.crypto_analyzer import CryptoAnalyzer
from src.tools.network_tools import NetworkSniffer

class InteractionWorker:
    """
    (feature/js_re 分支版)
    一个轻量级的分析器，接收CDPDebugger的调试事件，
    调用AI进行JS逆向分析，并打印结果。
    """

    def __init__(self, config: dict, debug_q: Queue):
        self.config = config
        self.debug_q = debug_q
        self.logger = logging.getLogger(self.__class__.__name__)
        
        llm_config = self.config.get('llm_service', {})
        if llm_config and llm_config.get('api_config'):
            self.llm_client = AsyncOpenAI(base_url=llm_config['api_config'].get('base_url'), api_key=llm_config['api_config'].get('api_key'))
        else:
            self.llm_client = None
            
        # 初始化加密分析工具
        self.crypto_analyzer = CryptoAnalyzer()
            
        # 添加缓存机制，避免重复分析
        self.analysis_cache = {}  # 基于代码片段哈希的缓存
        self.max_cache_size = 100  # 最大缓存数量
        
        # 添加处理中的任务集合，避免并发处理相同任务
        self.processing_tasks = set()
        
        # JS Hook脚本内容
        self.js_hook_script = ""
        
        self.logger.info("InteractionWorker (JS逆向版) 初始化完成。")

    async def run(self):
        await self._load_js_hooks()
        self.logger.info("InteractionWorker (JS逆向版) 开始运行，等待调试事件...")
        while True:
            try:
                debug_event = await self.debug_q.get()
                # 异步处理事件，避免阻塞队列
                asyncio.create_task(self._process_debug_event(debug_event))
                self.debug_q.task_done()
            except asyncio.CancelledError:
                self.logger.info("InteractionWorker 收到关闭信号。")
                break
            except Exception as e:
                self.logger.error(f"处理调试事件时发生未知错误: {e}", exc_info=True)

    async def _load_js_hooks(self):
        """加载JS Hook脚本"""
        try:
            with open('src/tools/js_hooks.js', 'r', encoding='utf-8') as f:
                self.js_hook_script = f.read()
                self.logger.info("JS Reversing Hook脚本加载成功。")
        except Exception as e:
            self.logger.error(f"加载JS Reversing Hook脚本失败: {e}")

    async def _process_debug_event(self, debug_event: Dict[str, Any]):
        """处理调试事件的主方法，包含去重逻辑"""
        # 创建事件指纹
        event_fingerprint = self._create_event_fingerprint(debug_event)
        
        # 检查是否正在处理相同任务
        if event_fingerprint in self.processing_tasks:
            self.logger.debug(f"事件 {event_fingerprint} 正在处理中，跳过重复事件")
            return
            
        # 添加到处理中集合
        self.processing_tasks.add(event_fingerprint)
        
        try:
            await self._analyze_js_snippet(debug_event)
        finally:
            # 处理完成后从集合中移除
            self.processing_tasks.discard(event_fingerprint)

    def _create_event_fingerprint(self, debug_event: Dict[str, Any]) -> str:
        """创建事件指纹，用于识别重复事件"""
        # 基于URL、函数名和代码片段创建指纹
        url = debug_event.get('url', '')
        function_name = debug_event.get('function_name', '')
        code_snippet = debug_event.get('code_snippet', '')
        
        # 只取代码片段的一部分作为指纹，避免过长
        fingerprint_data = f"{url}|{function_name}|{code_snippet[:500]}"
        return hashlib.md5(fingerprint_data.encode('utf-8')).hexdigest()

    async def _analyze_js_snippet(self, debug_event: Dict[str, Any]):
        self.logger.info(f"接收到来自 {debug_event['url']} 的JS分析任务，触发事件: {debug_event['trigger']}")
        
        code_snippet = debug_event.get('code_snippet')
        variables = debug_event.get('variables')
        url = debug_event.get('url')
        network_data = debug_event.get('network_data', [])

        if not code_snippet or code_snippet == 'Source not available':
            self.logger.warning("调试事件中不包含代码片段，跳过AI分析。")
            return

        if not self.llm_client:
            self.logger.warning("LLM客户端未初始化，跳过AI分析。")
            return

        # 检查缓存
        code_hash = hashlib.md5(code_snippet.encode('utf-8')).hexdigest()
        if code_hash in self.analysis_cache:
            cached_result = self.analysis_cache[code_hash]
            self.logger.info(f"使用缓存的分析结果，URL: {url}")
            self._print_analysis_result(url, debug_event.get('function_name', 'anonymous'), cached_result, True)
            return

        # 进行静态分析以提供额外上下文
        static_analysis = self.crypto_analyzer.analyze_code_snippet(code_snippet)
        self.logger.debug(f"静态分析结果: {static_analysis}")

        prompt = get_js_re_prompt(code_snippet, variables, url, network_data)
        
        try:
            response_content = await self._call_llm(prompt)
            if response_content:
                # 使用静态分析增强AI分析结果
                enhanced_result = self._enhance_result_with_static_analysis(response_content, code_snippet)
                
                # 缓存结果
                if len(self.analysis_cache) >= self.max_cache_size:
                    # 移除第一个缓存项（简单实现）
                    first_key = next(iter(self.analysis_cache))
                    del self.analysis_cache[first_key]
                
                self.analysis_cache[code_hash] = enhanced_result
                
                # 直接打印AI的分析结果
                self._print_analysis_result(url, debug_event.get('function_name', 'anonymous'), enhanced_result)

        except Exception as e:
            self.logger.error(f"调用LLM进行JS逆向分析时出错: {e}", exc_info=True)

    def _enhance_result_with_static_analysis(self, response_content: str, code_snippet: str) -> str:
        """使用静态分析增强AI分析结果"""
        # 尝试提取AI分析结果中的JSON部分
        json_result = self._extract_json_from_response(response_content)
        if json_result:
            # 使用加密分析工具增强结果
            enhanced_json = self.crypto_analyzer.enhance_analysis_with_static_patterns(json_result, code_snippet)
            # 将增强后的结果替换到原始响应中
            enhanced_response = re.sub(
                r"```(?:json)?\s*({.*?})\s*```", 
                f"```json\n{json.dumps(enhanced_json, indent=2, ensure_ascii=False)}\n```",
                response_content,
                flags=re.DOTALL
            )
            return enhanced_response
        return response_content

    def _print_analysis_result(self, url: str, function_name: str, response_content: str, from_cache: bool = False):
        """打印分析结果，提取并格式化JSON部分"""
        cache_indicator = " (来自缓存)" if from_cache else ""
        
        # 尝试提取并格式化JSON部分
        json_result = self._extract_json_from_response(response_content)
        if json_result:
            formatted_json = json.dumps(json_result, indent=2, ensure_ascii=False)
            self.logger.info(f"\n--- AI逆向分析结果{cache_indicator} ---\nURL: {url}\n触发函数: {function_name}\n{response_content}\n结构化结果:\n{formatted_json}\n-----------------------")
        else:
            self.logger.info(f"\n--- AI逆向分析结果{cache_indicator} ---\nURL: {url}\n触发函数: {function_name}\n{response_content}\n-----------------------")

    def _extract_json_from_response(self, response_content: str) -> Optional[Dict]:
        """从AI响应中提取JSON部分"""
        try:
            # 尝试找到代码块中的JSON
            json_match = re.search(r"```(?:json)?\s*({.*?})\s*```", response_content, re.DOTALL)
            if json_match:
                json_str = json_match.group(1)
                return json.loads(json_str)
            
            # 如果没有找到代码块，尝试直接解析整个响应
            return json.loads(response_content)
        except:
            # 如果解析失败，返回None
            return None

    async def _call_llm(self, prompt: str) -> Optional[str]:
        try:
            cfg = self.config['llm_service']['api_config']
            messages = [{"role": "system", "content": "你是一名顶级的JavaScript逆向工程专家，尤其擅长分析和破解前端加密逻辑。"}, {"role": "user", "content": prompt}]
            
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
            await log_ai_dialogue(prompt, content, self.config.get('logging', {}).get('ai_dialogues_file', './logs/ai_dialogues.jsonl'))
            return content

        except asyncio.TimeoutError:
            self.logger.error("LLM调用超时。")
            return "[分析超时]"
        except Exception as e:
            self.logger.error(f"LLM调用失败: {e}")
            return f"[分析失败: {e}]"