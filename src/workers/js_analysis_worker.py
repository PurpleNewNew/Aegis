import asyncio
import json
import logging
import openai # 使用openai库
import chromadb
from asyncio import Queue
from src.utils.ai_logger import log_ai_dialogue
from src.prompts.prompt import get_js_analysis_prompt

class JSAnalysisWorker:
    """
    分析JavaScript文件内容，寻找硬编码的密钥、API端点和安全漏洞。
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
        
        try:
            self.chroma_client = chromadb.PersistentClient(path=self.config['chromadb']['path'])
            self.collection = self.chroma_client.get_or_create_collection(name=self.config['chromadb']['collection_name'])
            self.logger.info(f"已连接到ChromaDB并获取到集合 '{self.config['chromadb']['collection_name']}'.")
        except Exception as e:
            self.logger.error(f"初始化ChromaDB失败: {e}", exc_info=True)
            self.chroma_client = None

    async def run(self):
        self.logger.info("JS分析Worker正在运行。")
        try:
            while True:
                context = await self.input_q.get()
                url = context.get('url')
                js_content = context.get('content')
                self.logger.info(f"正在分析JS文件: {url}")

                # 1. 检索记忆
                memories = None
                if self.chroma_client:
                    try:
                        memories = self.collection.query(query_texts=[url], n_results=3)
                        self.logger.info(f"为JS文件URL检索到 {len(memories.get('documents', [[]])[0])} 条记忆。")
                    except Exception as e:
                        self.logger.error(f"查询ChromaDB时出错: {e}")

                # 2. 构建提示
                prompt = get_js_analysis_prompt(url, js_content, memories)

                # 3. 从LLM服务生成分析
                try:
                    response = await self.llm_client.chat.completions.create(
                        model=self.config['llm_service']['model_name'],
                        messages=[{'role': 'user', 'content': prompt}],
                        temperature=0.2
                    )
                    analysis_text = response.choices[0].message.content
                    self.logger.info(f"已收到对 {url} 的LLM分析。")

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
                            self.logger.info(f"AI分析完成，未在JS文件 {url} 中发现任何安全问题。")
                    except json.JSONDecodeError:
                        self.logger.error(f"无法解析来自LLM的JSON响应: {analysis_text}")

                except Exception as e:
                    self.logger.error(f"与LLM服务通信时出错: {e}", exc_info=True)

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("JS分析Worker正在关闭。")
        except Exception as e:
            self.logger.error(f"在JSAnalysisWorker中发生错误: {e}", exc_info=True)