import asyncio
import logging
from asyncio import Queue

class Dispatcher:
    """
    从队列中提取精炼的上下文，并根据上下文类型或内容
    将其分发到专用的AI Worker队列中。
    """

    def __init__(self, input_q: Queue, soft_q: Queue, reverse_q: Queue, js_q: Queue):
        """
        初始化调度器。

        Args:
            input_q: 用于提取精炼上下文的输入队列。
            soft_q: 用于软漏洞分析任务的队列。
            reverse_q: 用于逆向工程分析任务的队列。
            js_q: 用于JavaScript文件分析任务的队列。
        """
        self.input_q = input_q
        self.soft_q = soft_q
        self.reverse_q = reverse_q
        self.js_q = js_q
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

                context_type = context.get('event_type')

                # 根据事件类型进行路由
                if context_type == 'network_request':
                    self.logger.info(f"正在将 {context['url']} 的'网络请求'路由到AI Workers。")
                    # 网络请求上下文在旧版中被错误地标记为 'type', 在新版中应为 'event_type'
                    # 为了兼容性，我们假设它可能仍然是 'type'
                    context['type'] = 'network_request' # 确保type字段存在
                    await self.soft_q.put(context)
                    await self.reverse_q.put(context)
                elif context_type == 'javascript_file':
                    self.logger.info(f"正在将JS文件 {context['url']} 路由到JS分析器。")
                    await self.js_q.put(context)
                else:
                    # 兼容旧的 'type' 字段
                    legacy_type = context.get('type')
                    if legacy_type == 'network_request':
                         self.logger.info(f"正在将 {context['url']} 的'网络请求'路由到AI Workers。")
                         await self.soft_q.put(context)
                         await self.reverse_q.put(context)
                    else:
                        self.logger.warning(f"没有针对上下文类型 '{context_type or legacy_type}' 的特定路由。正在丢弃。")

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("调度器正在关闭。")
        except Exception as e:
            self.logger.error(f"调度器发生错误: {e}", exc_info=True)