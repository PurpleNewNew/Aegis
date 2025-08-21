import asyncio
import logging
import json
from typing import Dict, Any, Optional
from asyncio import Queue
from openai import AsyncOpenAI

from src.prompts.prompt import get_js_re_prompt
from src.utils.ai_logger import log_ai_dialogue

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
        self.logger.info("InteractionWorker (JS逆向版) 初始化完成。")

    async def run(self):
        self.logger.info("InteractionWorker (JS逆向版) 开始运行，等待调试事件...")
        while True:
            try:
                debug_event = await self.debug_q.get()
                await self._analyze_js_snippet(debug_event)
                self.debug_q.task_done()
            except asyncio.CancelledError:
                self.logger.info("InteractionWorker 收到关闭信号。")
                break
            except Exception as e:
                self.logger.error(f"处理调试事件时发生未知错误: {e}", exc_info=True)

    async def _analyze_js_snippet(self, debug_event: Dict[str, Any]):
        self.logger.info(f"接收到来自 {debug_event['url']} 的JS分析任务，触发事件: {debug_event['trigger']}")
        
        code_snippet = debug_event.get('code_snippet')
        variables = debug_event.get('variables')
        url = debug_event.get('url')

        if not code_snippet or code_snippet == 'Source not available':
            self.logger.warning("调试事件中不包含代码片段，跳过AI分析。")
            return

        if not self.llm_client:
            self.logger.warning("LLM客户端未初始化，跳过AI分析。")
            return

        prompt = get_js_re_prompt(code_snippet, variables, url)
        
        try:
            response_content = await self._call_llm(prompt)
            if response_content:
                # 直接打印AI的分析结果
                self.logger.info(f"\n--- AI逆向分析结果 ---\nURL: {url}\n触发函数: {debug_event.get('function_name', 'anonymous')}\n{response_content}\n-----------------------")

        except Exception as e:
            self.logger.error(f"调用LLM进行JS逆向分析时出错: {e}", exc_info=True)

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