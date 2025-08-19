
import asyncio
import logging
from asyncio import Queue
from typing import List

class Broadcaster:
    """
    实现发布/订阅（Pub/Sub）模式。它从一个输入队列中拉取消息，
    并将其副本放入多个输出队列中以进行并行处理。
    """

    def __init__(self, input_q: Queue, output_queues: List[Queue]):
        self.input_q = input_q
        self.output_queues = output_queues
        self.logger = logging.getLogger(self.__class__.__name__)

    async def run(self):
        self.logger.info(f"广播器正在运行，分发到 {len(self.output_queues)} 个队列。")
        try:
            while True:
                message = await self.input_q.get()
                self.logger.debug(f"正在广播消息: {message}")
                for q in self.output_queues:
                    await q.put(message)
                self.logger.info(f"已将来自 '{message.get('worker')}' 的消息广播到所有输出队列。")
                self.input_q.task_done()
        except asyncio.CancelledError:
            self.logger.info("广播器正在关闭。")
        except Exception as e:
            self.logger.error(f"广播器发生错误: {e}", exc_info=True)
