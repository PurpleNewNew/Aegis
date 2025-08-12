import asyncio
import json
import logging
import ollama
import chromadb
from asyncio import Queue
from src.utils.ai_logger import log_ai_dialogue
from src.prompts.prompt import get_hard_vuln_prompt # 导入集中的提示词函数

class AIReverseWorker:
    """
    通过推断分析上下文中的“硬”漏洞（如SQLi, RCE等），
    使用由RAG驱动的LLM调用。
    """

    def __init__(self, input_q: Queue, output_q: Queue, config: dict):
        self.input_q = input_q
        self.output_q = output_q
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        self.ollama_client = ollama.AsyncClient(
            host=self.config['ollama']['host'],
            timeout=self.config['ollama']['timeout']
        )
        
        try:
            self.chroma_client = chromadb.PersistentClient(path=self.config['chromadb']['path'])
            self.collection = self.chroma_client.get_or_create_collection(name=self.config['chromadb']['collection_name'])
            self.logger.info(f"已连接到ChromaDB并获取到集合 '{self.config['chromadb']['collection_name']}'.")
        except Exception as e:
            self.logger.error(f"初始化ChromaDB失败: {e}", exc_info=True)
            self.chroma_client = None

    async def run(self):
        self.logger.info("AI逆向分析Worker正在运行。")
        try:
            while True:
                context = await self.input_q.get()
                self.logger.info(f"正在为 {context['url']} 分析硬漏洞。")

                # 1. 检索记忆
                memories = None
                if self.chroma_client:
                    try:
                        memories = self.collection.query(query_texts=[context['url']], n_results=3)
                        self.logger.info(f"为URL检索到 {len(memories.get('documents', [[]])[0])} 条记忆。")
                    except Exception as e:
                        self.logger.error(f"查询ChromaDB时出错: {e}")

                # 2. 构建提示
                prompt = get_hard_vuln_prompt(context, memories)

                # 3. 生成分析
                try:
                    response = await self.ollama_client.chat(
                        model=self.config['ollama']['model'],
                        messages=[{'role': 'user', 'content': prompt}]
                    )
                    analysis_text = response['message']['content']
                    self.logger.info(f"已收到对 {context['url']} 的Ollama分析。")

                    await log_ai_dialogue(prompt, analysis_text, self.config['logging']['ai_dialogues_file'])

                    # 4. 解析JSON响应并发送结果
                    try:
                        findings = json.loads(analysis_text)
                        if findings: # 仅当有发现时才发送
                            analysis_result = {
                                'source_context': context,
                                'findings': findings, # 这是一个对象列表
                                'worker': self.__class__.__name__
                            }
                            await self.output_q.put(analysis_result)
                    except json.JSONDecodeError:
                        self.logger.error(f"无法解析来自Ollama的JSON响应: {analysis_text}")

                except Exception as e:
                    self.logger.error(f"与Ollama通信时出错: {e}", exc_info=True)

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("AI逆向分析Worker正在关闭。")
        except Exception as e:
            self.logger.error(f"在AIReverseWorker中发生错误: {e}", exc_info=True)