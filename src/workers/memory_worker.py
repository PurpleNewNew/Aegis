
import asyncio
import logging
import chromadb
import hashlib
from asyncio import Queue

class MemoryWorker:
    """
    提取最终的分析结果，并将关键信息（AI的分析）作为记忆
    存储在ChromaDB向量数据库中，以供未来的RAG检索使用。
    """

    def __init__(self, input_q: Queue, config: dict):
        """
        初始化Worker。

        Args:
            input_q: 用于提取最终分析结果的输入队列。
            config: 应用程序的配置字典。
        """
        self.input_q = input_q
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        try:
            self.chroma_client = chromadb.PersistentClient(path=self.config['chromadb']['path'])
            self.collection = self.chroma_client.get_or_create_collection(name=self.config['chromadb']['collection_name'])
            self.logger.info(f"已连接到ChromaDB并获取到集合 '{self.config['chromadb']['collection_name']}'.")
        except Exception as e:
            self.logger.error(f"初始化ChromaDB失败: {e}", exc_info=True)
            self.chroma_client = None # 禁用数据库功能

    def create_memory_id(self, text: str) -> str:
        """
        为记忆文档创建一个一致且唯一的ID。
        """
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    async def run(self):
        """
        Worker的主循环。
        它持续地提取结果并将其存储为记忆。
        """
        if not self.chroma_client:
            self.logger.warning("ChromaDB未初始化。记忆Worker将不会运行。")
            return

        self.logger.info("记忆Worker正在运行。")
        try:
            while True:
                result = await self.input_q.get()
                source_context = result.get('source_context', {})
                findings = result.get('findings', [])
                worker_name = result.get('worker')

                if not findings:
                    self.input_q.task_done()
                    continue

                self.logger.info(f"正在为来自 {worker_name} 的 {len(findings)} 个发现创建记忆。")

                docs_to_add = []
                ids_to_add = []
                metadatas_to_add = []

                for finding in findings:
                    # 为每个发现创建一个简洁、有意义的记忆文档
                    memory_doc = (
                        f"对于URL '{source_context.get('initiator_url')}', 由 '{worker_name}' 发现一个置信度为 '{finding.get('confidence')}' 的 '{finding.get('vulnerability')}' (严重性: {finding.get('severity')})。 "
                        f"推理过程: {finding.get('reasoning')}"
                    )
                    memory_id = self.create_memory_id(memory_doc)
                    
                    docs_to_add.append(memory_doc)
                    ids_to_add.append(memory_id)
                    metadatas_to_add.append({
                        'source_url': source_context.get('initiator_url'),
                        'vulnerability': finding.get('vulnerability'),
                        'worker': worker_name
                    })

                try:
                    if docs_to_add:
                        self.collection.add(
                            ids=ids_to_add,
                            documents=docs_to_add,
                            metadatas=metadatas_to_add
                        )
                        self.logger.info(f"成功存储了 {len(docs_to_add)} 条新记忆。")
                except Exception as e:
                    self.logger.warning(f"无法存储记忆 (可能部分已存在): {e}")

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("记忆Worker正在关闭。")
        except Exception as e:
            self.logger.error(f"在MemoryWorker中发生错误: {e}", exc_info=True)
