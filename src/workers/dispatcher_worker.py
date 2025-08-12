
import asyncio
import logging
from asyncio import Queue

class Dispatcher:
    """
    从队列中提取精炼的上下文，并根据上下文类型或内容
    将其分发到专用的AI Worker队列中。
    """

    def __init__(self, input_q: Queue, soft_q: Queue, reverse_q: Queue):
        """
        初始化调度器。

        Args:
            input_q: 用于提取精炼上下文的输入队列。
            soft_q: 用于软漏洞分析任务的队列。
            reverse_q: 用于逆向工程分析任务的队列。
        """
        self.input_q = input_q
        self.soft_q = soft_q
        self.reverse_q = reverse_q
        self.logger = logging.getLogger(self.__class__.__name__)

    async def run(self):
        """
        调度器的主循环。
        它持续地提取上下文并进行路由。
        """
        self.logger.info("调度器正在运行。")
        try:
            while True:
                context = await self.input_q.get()
                self.logger.debug(f"收到上下文: {context}")

                # 简单的路由逻辑：将网络请求发送到两个分析流水线。
                if context.get('type') == 'network_request':
                    self.logger.info(f"正在将 {context['url']} 的'网络请求'路由到AI Workers。")
                    # 我们将相同的上下文放入两个队列中以进行并行分析。
                    await self.soft_q.put(context)
                    await self.reverse_q.put(context)
                else:
                    self.logger.warning(f"没有针对上下文类型 {context.get('type')} 的特定路由。正在丢弃。")

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("调度器正在关闭。")
        except Exception as e:
            self.logger.error(f"调度器发生错误: {e}", exc_info=True)
