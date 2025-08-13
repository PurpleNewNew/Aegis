
import asyncio
import logging
import os
import tempfile
from openai import AsyncOpenAI
import chromadb
import json
from asyncio import Queue
from src.utils.ai_logger import log_ai_dialogue
from src.prompts.prompt import get_correlation_prompt

class CorrelationWorker:
    """
    接收包含网络请求和JS代码摘要的上下文包，
    并根据配置模式（API或CLI）调用LLM进行最终的、高层次的关联分析。
    """

    def __init__(self, input_q: Queue, output_q: Queue, config: dict):
        self.input_q = input_q
        self.output_q = output_q
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        self.llm_mode = self.config['llm_service']['mode']
        self.logger.info(f"关联分析器以 '{self.llm_mode}' 模式初始化。")

        if self.llm_mode == 'api':
            api_config = self.config['llm_service']['api_config']
            self.llm_client = AsyncOpenAI(
                base_url=api_config['base_url'],
                api_key=api_config['api_key'],
            )
        elif self.llm_mode != 'cli':
            raise ValueError(f"未知的LLM服务模式: {self.llm_mode}")

        try:
            chroma_config = self.config['chromadb']
            self.chroma_client = chromadb.PersistentClient(path=chroma_config['path'])
            self.collection = self.chroma_client.get_or_create_collection(name=chroma_config['collection_name'])
            self.logger.info(f"已连接到ChromaDB并获取到集合 '{chroma_config['collection_name']}'.")
        except Exception as e:
            self.logger.error(f"初始化ChromaDB失败: {e}", exc_info=True)
            self.chroma_client = None

    async def _get_analysis_from_api(self, prompt: str) -> str:
        api_config = self.config['llm_service']['api_config']
        response = await self.llm_client.chat.completions.create(
            model=api_config['model_name'],
            messages=[{'role': 'user', 'content': prompt}],
            timeout=api_config['timeout']
        )
        return response.choices[0].message.content

    async def _get_analysis_from_cli(self, prompt: str) -> str:
        cli_config = self.config['llm_service']['cli_config']
        analysis_text = ""
        prompt_file_path = None
        output_file_path = None

        try:
            # 创建临时文件并获取路径
            with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".txt", encoding='utf-8') as prompt_file:
                prompt_file_path = prompt_file.name
                await prompt_file.write(prompt)
            
            with tempfile.NamedTemporaryFile(mode='r', delete=False, suffix=".txt", encoding='utf-8') as output_file:
                output_file_path = output_file.name

            # 构建并执行命令
            command = cli_config['command_template'].format(
                prompt_file=prompt_file_path,
                output_file=output_file_path
            )
            self.logger.info(f"执行CLI命令: {command}")
            self.logger.info(f"要实时查看输出, 请在另一个终端运行: tail -f {output_file_path}")
            
            # run_shell_command 是一个可用的全局工具
            result = await run_shell_command(command, description="Call external AI CLI")

            # 从输出文件读取结果
            if result.get('exit_code') == 0:
                with open(output_file_path, 'r', encoding='utf-8') as f:
                    analysis_text = f.read()
            else:
                err_msg = f"CLI命令执行失败: {result.get('stderr')}"
                self.logger.error(err_msg)
                analysis_text = err_msg

        finally:
            # 清理临时文件
            if prompt_file_path and os.path.exists(prompt_file_path):
                os.remove(prompt_file_path)
            if output_file_path and os.path.exists(output_file_path):
                os.remove(output_file_path)
        
        return analysis_text

    async def run(self):
        self.logger.info("关联分析Worker正在运行。")
        try:
            while True:
                context_package = await self.input_q.get()
                initiator_url = context_package.get('initiator_url')
                self.logger.info(f"开始对上下文 '{initiator_url}' 进行最终关联分析。")

                memories = None
                if self.chroma_client:
                    try:
                        memories = self.collection.query(query_texts=[initiator_url], n_results=5)
                        self.logger.info(f"为上下文 '{initiator_url}' 检索到 {len(memories.get('documents', [[]])[0])} 条记忆。")
                    except Exception as e:
                        self.logger.error(f"查询ChromaDB时出错: {e}")

                prompt = get_correlation_prompt(context_package, memories)
                analysis_text = ""

                try:
                    if self.llm_mode == 'api':
                        analysis_text = await self._get_analysis_from_api(prompt)
                    elif self.llm_mode == 'cli':
                        analysis_text = await self._get_analysis_from_cli(prompt)

                    self.logger.info(f"已收到对 '{initiator_url}' 的LLM最终关联分析。")
                    await log_ai_dialogue(prompt, analysis_text, self.config['logging']['ai_dialogues_file'])

                    try:
                        findings = json.loads(analysis_text)
                        if findings:
                            analysis_result = {
                                'source_context': context_package,
                                'findings': findings,
                                'worker': self.__class__.__name__
                            }
                            await self.output_q.put(analysis_result)
                    except json.JSONDecodeError:
                        self.logger.error(f"无法解析来自LLM的JSON响应: {analysis_text}")

                except Exception as e:
                    self.logger.error(f"与LLM服务通信时出错: {e}", exc_info=True)

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("关联分析Worker正在关闭。")
        except Exception as e:
            self.logger.error(f"在CorrelationWorker中发生错误: {e}", exc_info=True)
