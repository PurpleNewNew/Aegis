
import asyncio
import logging
from openai import AsyncOpenAI # 替换为OpenAI库
import chromadb
import json
from asyncio import Queue
from src.utils.ai_logger import log_ai_dialogue
from src.prompts.prompt import get_holistic_analysis_prompt

class HolisticAnalysisWorker:
    """
    接收一个完整的、包含多个事件的上下文包，
    并调用LLM进行整体性、关联性分析。
    """

    def __init__(self, input_q: Queue, output_q: Queue, config: dict):
        self.input_q = input_q
        self.output_q = output_q
        self.config = config # 接收完整的config对象
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # 初始化OpenAI客户端以连接LM Studio
        llm_config = self.config['llm_service']
        self.llm_client = AsyncOpenAI(
            base_url=llm_config['base_url'],
            api_key=llm_config['api_key'],
        )
        
        try:
            # 从完整的config中获取ChromaDB的配置
            chroma_config = self.config['chromadb']
            self.chroma_client = chromadb.PersistentClient(path=chroma_config['path'])
            self.collection = self.chroma_client.get_or_create_collection(name=chroma_config['collection_name'])
            self.logger.info(f"已连接到ChromaDB并获取到集合 '{chroma_config['collection_name']}'.")
        except Exception as e:
            self.logger.error(f"初始化ChromaDB失败: {e}", exc_info=True)
            self.chroma_client = None

    async def run(self):
        self.logger.info("整体分析Worker正在运行。")
        try:
            while True:
                context_package = await self.input_q.get()
                initiator_url = context_package.get('initiator_url')
                self.logger.info(f"开始对上下文 '{initiator_url}' 进行整体性分析。")

                # 1. 检索与主URL相关的记忆
                memories = None
                if self.chroma_client:
                    try:
                        memories = self.collection.query(query_texts=[initiator_url], n_results=5)
                        self.logger.info(f"为上下文 '{initiator_url}' 检索到 {len(memories.get('documents', [[]])[0])} 条记忆。")
                    except Exception as e:
                        self.logger.error(f"查询ChromaDB时出错: {e}")

                # 2. 构建大师级Prompt
                prompt = get_holistic_analysis_prompt(context_package, memories)

                # 3. 从兼容OpenAI的LLM服务生成分析
                try:
                    llm_config = self.config['llm_service']
                    self.logger.info("准备调用LLM进行分析...") # 调试日志
                    response = await self.llm_client.chat.completions.create(
                        model=llm_config['model_name'],
                        messages=[{'role': 'user', 'content': prompt}],
                        timeout=llm_config['timeout']
                    )
                    self.logger.info("已收到LLM的分析结果，正在处理...") # 调试日志
                    analysis_text = response.choices[0].message.content
                    self.logger.info(f"已收到对 '{initiator_url}' 的LLM整体性分析。")

                    await log_ai_dialogue(prompt, analysis_text, self.config['logging']['ai_dialogues_file'])

                    # 4. 解析JSON响应并发送结果
                    try:
                        findings = json.loads(analysis_text)
                        if findings: # 仅当有发现时才发送
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
            self.logger.info("整体分析Worker正在关闭。")
        except Exception as e:
            self.logger.error(f"在HolisticAnalysisWorker中发生错误: {e}", exc_info=True)
