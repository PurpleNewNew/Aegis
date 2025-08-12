import asyncio
import logging
import json
import aiofiles
from asyncio import Queue

class JsonlWriterWorker:
    """
    从队列中拉取数据，并将其异步写入.jsonl文件。
    队列中的每一项都会成为文件中的新一行。
    """

    def __init__(self, input_q: Queue, file_path: str):
        """
        初始化写入器Worker。

        Args:
            input_q: 用于拉取数据的输入队列。
            file_path: 要写入的.jsonl文件的路径。
        """
        self.input_q = input_q
        self.file_path = file_path
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.info(f"捕获的数据将被写入到 {self.file_path}")

    async def run(self):
        """
        Worker的主循环。
        它持续地拉取数据并写入文件。
        """
        self.logger.info("JSONL写入器Worker正在运行。")
        try:
            while True:
                # 从输入队列获取数据
                data = await self.input_q.get()
                
                try:
                    # 将JSON对象作为新行追加到文件中
                    async with aiofiles.open(self.file_path, mode='a', encoding='utf-8') as f:
                        await f.write(json.dumps(data) + '\n')
                    self.logger.debug(f"已将 {data.get('url')} 的上下文写入到 {self.file_path}")
                except Exception as e:
                    self.logger.error(f"写入到 {self.file_path} 失败: {e}")

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("JSONL写入器Worker正在关闭。" )
        except Exception as e:
            self.logger.error(f"在JsonlWriterWorker中发生错误: {e}", exc_info=True)