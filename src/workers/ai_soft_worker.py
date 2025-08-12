
import asyncio
import json
import logging
import openai # 使用openai库
import chromadb
from asyncio import Queue
from src.utils.ai_logger import log_ai_dialogue
from src.prompts.prompt import get_soft_vuln_prompt

class AISoftWorker:
    """
    使用由RAG驱动的LLM调用来分析上下文中的“软”漏洞。
    """

    def __init__(self, input_q: Queue, output_q: Queue, config: dict):
        self.input_q = input_q
        self.output_q = output_q
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # 初始化OpenAI客户端以连接LM-Studio
        self.llm_client = openai.AsyncOpenAI(
            base_url=self.config['llm_service']['base_url'],
            api_key=self.config['llm_service']['api_key'],
            timeout=self.config['llm_service']['timeout']
        )
        
        # 初始化ChromaDB客户端
        try:
            self.chroma_client = chromadb.PersistentClient(path=self.config['chromadb']['path'])
            self.collection = self.chroma_client.get_or_create_collection(name=self.config['chromadb']['collection_name'])
            self.logger.info(f"已连接到ChromaDB并获取到集合 '{self.config['chromadb']['collection_name']}'.")
        except Exception as e:
            self.logger.error(f"初始化ChromaDB失败: {e}", exc_info=True)
            self.chroma_client = None # 禁用数据库功能

    async def run(self):
        self.logger.info("AI软漏洞Worker正在运行。")
        try:
            while True:
                context = await self.input_q.get()
                self.logger.info(f"正在为 {context['url']} 分析软漏洞。")

                # 1. 从ChromaDB检索记忆
                memories = None
                if self.chroma_client:
                    try:
                        memories = self.collection.query(query_texts=[context['url']], n_results=3)
                        self.logger.info(f"为URL检索到 {len(memories.get('documents', [[]])[0])} 条记忆。")
                    except Exception as e:
                        self.logger.error(f"查询ChromaDB时出错: {e}")

                # 2. 使用集中化函数构建提示
                prompt = get_soft_vuln_prompt(context, memories)

                # 3. 从LLM服务生成分析
                try:
                    response = await self.llm_client.chat.completions.create(
                        model=self.config['llm_service']['model_name'],
                        messages=[{'role': 'user', 'content': prompt}],
                        temperature=0.2 # 降低随机性以获得更稳定的JSON输出
                    )
                    analysis_text = response.choices[0].message.content
                    self.logger.info(f"已收到对 {context['url']} 的LLM分析。")

                    await log_ai_dialogue(prompt, analysis_text, self.config['logging']['ai_dialogues_file'])

                    # 4. 解析JSON响应并发送结果
                    try:
                        findings = json.loads(analysis_text)
                        if findings:
                            analysis_result = {
                                'source_context': context,
                                'findings': findings,
                                'worker': self.__class__.__name__
                            }
                            await self.output_q.put(analysis_result)
                        else:
                            self.logger.info(f"AI分析完成，未在 {context['url']} 中发现任何软漏洞。")
                    except json.JSONDecodeError:
                        self.logger.error(f"无法解析来自LLM的JSON响应: {analysis_text}")

                except Exception as e:
                    self.logger.error(f"与LLM服务通信时出错: {e}", exc_info=True)

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("AI软漏洞Worker正在关闭。")
        except Exception as e:
            self.logger.error(f"在AISoftWorker中发生错误: {e}", exc_info=True)
