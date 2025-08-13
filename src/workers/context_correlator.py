
import asyncio
import logging
from asyncio import Queue
from typing import Dict, Any
from time import time

class ContextCorrelator:
    """
    从多个源队列接收事件（网络请求、JS摘要），将它们按发起者URL聚合成一个扫描上下文，
    并在满足触发条件（关键行为或超时）时，将上下文包发送出去进行最终的关联分析。
    """

    def __init__(self, request_q: Queue, summarized_js_q: Queue, output_q: Queue, inactivity_timeout: int = 5):
        """
        初始化关联器。

        Args:
            request_q: 接收网络请求事件的输入队列。
            summarized_js_q: 接收带有摘要的JS文件事件的输入队列。
            output_q: 发送打包后上下文的输出队列。
            inactivity_timeout: 页面无新事件后，等待多少秒才打包发送。
        """
        self.request_q = request_q
        self.summarized_js_q = summarized_js_q
        self.output_q = output_q
        self.inactivity_timeout = inactivity_timeout
        self.logger = logging.getLogger(self.__class__.__name__)
        self.contexts: Dict[str, Dict[str, Any]] = {}

    async def _add_event_to_context(self, event: dict):
        """将单个事件添加到其对应的上下文中。"""
        initiator_url = event.get('initiator_url')
        if not initiator_url:
            return

        if initiator_url not in self.contexts:
            self.contexts[initiator_url] = {
                'initiator_url': initiator_url,
                'requests': [],
                'summarized_js': [], # 存储带有摘要的JS事件
            }
            self.logger.info(f"为 '{initiator_url}' 创建了新的扫描上下文。")

        context = self.contexts[initiator_url]
        event_type = event.get('event_type')

        if event_type == 'request':
            context['requests'].append(event)
        elif event_type == 'javascript_file': # JS摘要事件也使用这个类型
            context['summarized_js'].append(event)
        
        context['last_updated'] = time()
        self.logger.debug(f"事件 {event_type} 已添加到 '{initiator_url}' 的上下文中。")

        # 关键行为触发器
        if event_type == 'request' and event.get('method') == 'POST':
            self.logger.info(f"检测到关键行为 (POST请求)，立即为 '{initiator_url}' 触发分析。")
            await self.package_and_send(initiator_url)

    async def _consume_queue(self, queue: Queue):
        """通用协程，用于消费一个队列中的所有事件。"""
        while True:
            event = await queue.get()
            await self._add_event_to_context(event)
            queue.task_done()

    async def package_and_send(self, initiator_url: str):
        """安全地打包并发送指定URL的上下文。"""
        if initiator_url in self.contexts:
            context_package = self.contexts.pop(initiator_url)
            await self.output_q.put(context_package)
            self.logger.info(f"上下文 '{initiator_url}' 已打包并发送进行分析。")

    async def timeout_manager(self):
        """定期检查并处理不活跃的上下文（稳定状态检测器）。"""
        check_interval = 2
        self.logger.info(f"稳定状态检测器已启动，检测间隔 {check_interval}s，不活跃超时阈值 {self.inactivity_timeout}s。")
        while True:
            await asyncio.sleep(check_interval)
            now = time()
            ready_urls = [url for url, data in list(self.contexts.items()) if now - data.get('last_updated', 0) > self.inactivity_timeout]
            
            for url in ready_urls:
                self.logger.info(f"检测到 '{url}' 已进入稳定状态。")
                await self.package_and_send(url)

    async def run(self):
        """
        Worker的主循环，并发地消费多个输入队列并管理上下文。
        """
        self.logger.info("上下文关联器正在运行 (v4.0 - 多队列输入模式)。")
        
        # 并发运行两个消费者和超时管理器
        tasks = [
            asyncio.create_task(self.timeout_manager()),
            asyncio.create_task(self._consume_queue(self.request_q)),
            asyncio.create_task(self._consume_queue(self.summarized_js_q))
        ]

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            self.logger.info("上下文关联器正在关闭。")
            self.logger.info("正在处理所有剩余的上下文...")
            for initiator_url in list(self.contexts.keys()):
                await self.package_and_send(initiator_url)
        # 不需要额外的finally，因为CancelledError会使gather中断

