import asyncio
import logging
import ollama
import chromadb
from asyncio import Queue
from src.utils.ai_logger import log_ai_dialogue
from src.prompts.prompt import get_soft_vuln_prompt # 导入集中的提示词函数

class AISoftWorker:
    """
    使用由RAG驱动的LLM调用来分析上下文中的“软”漏洞。
    """

    def __init__(self, input_q: Queue, output_q: Queue, config: dict):
        self.input_q = input_q
        self.output_q = output_q
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # 初始化Ollama客户端
        self.ollama_client = ollama.AsyncClient(
            host=self.config['ollama']['host'],
            timeout=self.config['ollama']['timeout']
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

                # 3. 从Ollama生成分析
                try:
                    response = await self.ollama_client.chat(
                        model=self.config['ollama']['model'],
                        messages=[{'role': 'user', 'content': prompt}]
                    )
                    analysis_text = response['message']['content']
                    self.logger.info(f"已收到对 {context['url']} 的Ollama分析。")

                    # 为调试记录对话
                    await log_ai_dialogue(prompt, analysis_text, self.config['logging']['ai_dialogues_file'])

                    # 4. 打包并发送结果
                    analysis_result = {
                        'source_context': context,
                        'analysis_text': analysis_text,
                        'worker': self.__class__.__name__
                    }
                    await self.output_q.put(analysis_result)

                except Exception as e:
                    self.logger.error(f"与Ollama通信时出错: {e}")

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("AI软漏洞Worker正在关闭。")
        except Exception as e:
            self.logger.error(f"在AISoftWorker中发生错误: {e}", exc_info=True)