
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
                self.logger.debug(f"收到来自 {result.get('worker')} 的结果用于记忆存储。")

                # 从结果中创建一个简洁的记忆文档。
                source_context = result.get('source_context', {})
                analysis_text = result.get('analysis_text', '')
                
                # 我们只想记忆实际的发现，而不是“未发现漏洞”这类消息。
                if "no vulnerabilities identified" in analysis_text.lower() or "未识别出" in analysis_text or not analysis_text:
                    self.logger.info("跳过对无发现结果的记忆。")
                    self.input_q.task_done()
                    continue

                memory_doc = (
                    f"当使用方法 '{source_context.get('method')}' 分析URL '{source_context.get('url')}' 时, "
                    f"产生了以下分析结果: {analysis_text}"
                )
                
                memory_id = self.create_memory_id(memory_doc)

                try:
                    # 将文档添加到集合中。ChromaDB会处理嵌入。
                    # 使用带有相同ID的`add`方法，在较新版本的chromadb中会更新现有条目，
                    # 在旧版本中会引发错误。这里我们假设需要唯一的记忆。
                    self.collection.add(
                        ids=[memory_id],
                        documents=[memory_doc],
                        metadatas=[{'source_url': source_context.get('url')}] # 可选的元数据
                    )
                    self.logger.info(f"成功为URL {source_context.get('url')} 存储了新记忆 (ID: {memory_id[:8]}...)." )
                except Exception as e:
                    # 如果我们尝试添加一个重复的ID，可能会发生这种情况，这没关系。
                    self.logger.warning(f"无法存储记忆 (可能已存在): {e}")

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("记忆Worker正在关闭。")
        except Exception as e:
            self.logger.error(f"在MemoryWorker中发生错误: {e}", exc_info=True)
