import asyncio
import logging
import json
import aiofiles
import os
from asyncio import Queue

class JsonlReaderWorker:
    """
    像tail一样追踪一个.jsonl文件，读取新增的行，并将解析后的JSON对象
    推送到队列中进行处理。
    """

    def __init__(self, output_q: Queue, file_path: str):
        """
        初始化读取器Worker。

        Args:
            output_q: 用于发送解析后JSON对象的输出队列。
            file_path: 要读取的.jsonl文件的路径。
        """
        self.output_q = output_q
        self.file_path = file_path
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.info(f"将从 {self.file_path} 读取(tail)数据")

    async def run(self):
        """
        Worker的主循环。它追踪文件并将新行推送到队列。
        """
        self.logger.info("JSONL读取器Worker正在运行。")
        
        # 在尝试读取之前，确保文件存在。
        # 写入器worker将会创建它。
        while not asyncio.get_event_loop().is_closed():
            try:
                if os.path.exists(self.file_path):
                    break
                self.logger.info(f"正在等待捕获文件 '{self.file_path}' 被创建...")
                await asyncio.sleep(2)
            except asyncio.CancelledError:
                return # 如果取消则退出

        try:
            async with aiofiles.open(self.file_path, mode='r', encoding='utf-8') as f:
                while True:
                    line = await f.readline()
                    if line:
                        try:
                            data = json.loads(line)
                            await self.output_q.put(data)
                            self.logger.info(f"已读取 {data.get('url')} 的上下文并发送到分析流水线。")
                        except json.JSONDecodeError:
                            self.logger.warning(f"跳过格式错误的JSON行: {line.strip()}")
                    else:
                        # 没有新行，稍等片刻再试
                        await asyncio.sleep(1)

        except asyncio.CancelledError:
            self.logger.info("JSONL读取器Worker正在关闭。")
        except Exception as e:
            self.logger.error(f"在JsonlReaderWorker中发生错误: {e}", exc_info=True)