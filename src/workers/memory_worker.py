import asyncio
import logging
import os

# 禁用ChromaDB遥测功能
os.environ['ANONYMIZED_TELEMETRY'] = 'False'
# os.environ['CHROMA_SERVER_NOFILE'] = '65536' # Windows不支持这个设置，删了

import chromadb
import hashlib
from asyncio import Queue

class MemoryWorker:
    """
    接收最终的调查结果，并为每个漏洞发现，创建一个包含“架构指纹”的
    富文本记忆，存入ChromaDB以供未来检索。
    """

    def __init__(self, input_q: Queue, config: dict):
        self.input_q = input_q
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        try:
            chroma_config = self.config['chromadb']
            self.chroma_client = chromadb.PersistentClient(path=chroma_config['path'])
            self.collection = self.chroma_client.get_or_create_collection(name=chroma_config['collection_name'])
            self.logger.info(f"已连接到ChromaDB并获取到集合 '{chroma_config['collection_name']}'.")
        except Exception as e:
            self.logger.error(f"初始化ChromaDB失败: {e}", exc_info=True)
            self.chroma_client = None

    def create_memory_id(self, text: str) -> str:
        """为记忆文档创建一个一致且唯一的ID。""" 
        return hashlib.sha256(text.encode('utf-8')).hexdigest()

    async def run(self):
        if not self.chroma_client:
            self.logger.warning("ChromaDB未初始化。记忆Worker将不会运行。")
            return

        self.logger.info("记忆Worker正在运行。")
        try:
            while True:
                result = await self.input_q.get()
                source_context = result.get('source_context', {})
                findings = result.get('findings', [])
                architecture = result.get('architecture', '未知架构')
                initiator_url = source_context.get('initiator_url', '未知URL')

                if not findings:
                    self.input_q.task_done()
                    continue

                self.logger.info(f"正在为 '{initiator_url}' 的 {len(findings)} 个发现创建架构化记忆。")

                docs_to_add = []
                ids_to_add = []
                metadatas_to_add = []

                for finding in findings:
                    # 优先使用'vulnerability'，其次是'type'，最后是'description'的前20个字符
                    vulnerability_name = finding.get('vulnerability') or finding.get('type') or str(finding.get('description', ''))[:20]

                    memory_doc = (
                        f"对于一个采用 '{architecture}' 架构的网站 ({initiator_url}), "
                        f"发现了一个置信度为 '{finding.get('confidence')}' 的 '{vulnerability_name}' (严重性: {finding.get('severity')}) 漏洞。 "
                        f"推理过程: {finding.get('reasoning')}"
                    )
                    memory_id = self.create_memory_id(memory_doc)
                    
                    docs_to_add.append(memory_doc)
                    ids_to_add.append(memory_id)
                    
                    # 构造元数据并进行清洗，确保没有None值
                    metadata = {
                        'source_url': initiator_url,
                        'architecture': architecture,
                        'vulnerability': vulnerability_name,
                        'severity': finding.get('severity'),
                        'confidence': finding.get('confidence')
                    }
                    sanitized_metadata = {k: (v if v is not None else "N/A") for k, v in metadata.items()}
                    metadatas_to_add.append(sanitized_metadata)

                try:
                    if docs_to_add:
                        self.collection.add(
                            ids=ids_to_add,
                            documents=docs_to_add,
                            metadatas=metadatas_to_add
                        )
                        self.logger.info(f"成功存储了 {len(docs_to_add)} 条关于 '{initiator_url}' 的新记忆。")
                except Exception as e:
                    self.logger.warning(f"无法存储记忆 (可能部分已存在): {e}")

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("记忆Worker正在关闭。")
        except Exception as e:
            self.logger.error(f"在MemoryWorker中发生错误: {e}", exc_info=True)