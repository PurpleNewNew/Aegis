import asyncio
import logging
import os
import tempfile
from openai import AsyncOpenAI
from asyncio import Queue
from src.utils.ai_logger import log_ai_dialogue
from src.prompts.prompt import get_js_summary_prompt
from ..tool_code import run_shell_command # Assuming run_shell_command is available

class JSSummarizerWorker:
    """
    接收JS文件，根据配置模式（API或CLI）调用LLM对其内容进行摘要，
    然后将带有摘要的事件发送到下一个队列。
    """

    def __init__(self, input_q: Queue, output_q: Queue, config: dict):
        self.input_q = input_q
        self.output_q = output_q
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        self.llm_mode = self.config['llm_service']['mode']
        self.logger.info(f"JS摘要器以 '{self.llm_mode}' 模式初始化。")

        if self.llm_mode == 'api':
            api_config = self.config['llm_service']['api_config']
            self.llm_client = AsyncOpenAI(
                base_url=api_config['base_url'],
                api_key=api_config['api_key'],
            )
        elif self.llm_mode != 'cli':
            raise ValueError(f"未知的LLM服务模式: {self.llm_mode}")

    async def _get_summary_from_api(self, prompt: str) -> str:
        api_config = self.config['llm_service']['api_config']
        response = await self.llm_client.chat.completions.create(
            model=api_config['model_name'],
            messages=[{'role': 'user', 'content': prompt}],
            timeout=api_config['timeout']
        )
        return response.choices[0].message.content

    async def _get_summary_from_cli(self, prompt: str) -> str:
        cli_config = self.config['llm_service']['cli_config']
        summary_text = ""
        # 使用临时文件来处理prompt和输出
        with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix=".txt", encoding='utf-8') as prompt_file,
             tempfile.NamedTemporaryFile(mode='r', delete=False, suffix=".txt", encoding='utf-8') as output_file:
            
            prompt_file_path = prompt_file.name
            output_file_path = output_file.name
            await prompt_file.write(prompt)
            await prompt_file.flush()

        try:
            command = cli_config['command_template'].format(
                prompt_file=prompt_file_path,
                output_file=output_file_path
            )
            self.logger.info(f"执行CLI命令: {command}")
            self.logger.info(f"要实时查看输出, 请在另一个终端运行: tail -f {output_file_path}")
            
            result = await run_shell_command(command, description="Call external AI CLI")
            if result.get('exit_code') == 0:
                summary_text = await output_file.read()
            else:
                self.logger.error(f"CLI命令执行失败: {result.get('stderr')}")
                summary_text = f"CLI命令执行失败: {result.get('stderr')}"

        finally:
            # 清理临时文件
            os.remove(prompt_file_path)
            os.remove(output_file_path)
        
        return summary_text

    async def run(self):
        self.logger.info("JS摘要器Worker正在运行。")
        try:
            while True:
                js_event = await self.input_q.get()
                js_url = js_event.get('url')
                js_content = js_event.get('content')
                self.logger.info(f"正在为JS文件生成摘要: {js_url}")

                prompt = get_js_summary_prompt(js_url, js_content)
                summary_text = ""

                try:
                    if self.llm_mode == 'api':
                        summary_text = await self._get_summary_from_api(prompt)
                    elif self.llm_mode == 'cli':
                        summary_text = await self._get_summary_from_cli(prompt)
                    
                    self.logger.info(f"已收到对 '{js_url}' 的摘要。")
                    await log_ai_dialogue(prompt, summary_text, self.config['logging']['ai_dialogues_file'])
                    js_event['summary'] = summary_text
                    await self.output_q.put(js_event)

                except Exception as e:
                    self.logger.error(f"为JS文件 '{js_url}' 生成摘要时与LLM通信出错: {e}", exc_info=True)

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("JS摘要器Worker正在关闭。")
        except Exception as e:
            self.logger.error(f"在JSSummarizerWorker中发生错误: {e}", exc_info=True)