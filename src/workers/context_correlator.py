import asyncio
import logging
from asyncio import Queue
from typing import Dict, Any
from time import time

class ContextCorrelator:
    """
    收集来自同一发起页面的多个事件，将它们聚合成一个扫描上下文。
    当一个页面的活动停止一段时间后，或发生一个关键行为（如POST请求）时，
    它会将这个上下文包发送出去进行整体分析。
    """

    def __init__(self, input_q: Queue, output_q: Queue, inactivity_timeout: int = 5):
        """
        初始化关联器。

        Args:
            input_q: 输入队列，接收精炼事件。
            output_q: 输出队列，发送打包后的上下文。
            inactivity_timeout: 页面无新事件后，等待多少秒才打包发送。
        """
        self.input_q = input_q
        self.output_q = output_q
        self.inactivity_timeout = inactivity_timeout
        self.logger = logging.getLogger(self.__class__.__name__)
        self.contexts: Dict[str, Dict[str, Any]] = {}

    async def package_and_send(self, initiator_url: str):
        """安全地打包并发送指定URL的上下文。"""
        if initiator_url in self.contexts:
            context_package = self.contexts.pop(initiator_url)
            await self.output_q.put(context_package)
            self.logger.info(f"上下文 '{initiator_url}' 已打包并发送进行分析。")

    async def timeout_manager(self):
        """定期检查并处理不活跃的上下文（稳定状态检测器）。"""
        check_interval = 2  # 每2秒检查一次
        self.logger.info(f"稳定状态检测器已启动，检测间隔 {check_interval}s，不活跃超时阈值 {self.inactivity_timeout}s。")
        while True:
            await asyncio.sleep(check_interval)
            now = time()
            ready_urls = []

            # 找出所有在inactivity_timeout时间内没有更新的上下文
            for initiator_url, context_data in list(self.contexts.items()):
                if now - context_data.get('last_updated', 0) > self.inactivity_timeout:
                    self.logger.info(f"检测到 '{initiator_url}' 已进入稳定状态。")
                    ready_urls.append(initiator_url)
            
            for url in ready_urls:
                await self.package_and_send(url)

    async def run(self):
        """
        Worker的主循环，负责接收事件、更新上下文，并根据关键行为触发分析。
        """
        self.logger.info("上下文关联器正在运行（v3.0 - 混合触发模式）。")
        manager_task = asyncio.create_task(self.timeout_manager())

        try:
            while True:
                event = await self.input_q.get()
                initiator_url = event.get('initiator_url')

                if not initiator_url:
                    self.input_q.task_done()
                    continue

                # 为当前URL创建或更新上下文
                if initiator_url not in self.contexts:
                    self.contexts[initiator_url] = {
                        'initiator_url': initiator_url,
                        'requests': [],
                        'js_files': [],
                    }
                    self.logger.info(f"为 '{initiator_url}' 创建了新的扫描上下文。")

                context = self.contexts[initiator_url]
                event_type = event.get('event_type')
                if event_type == 'network_request':
                    context['requests'].append(event)
                elif event_type == 'javascript_file':
                    context['js_files'].append(event)
                
                context['last_updated'] = time()
                self.logger.debug(f"事件已添加到 '{initiator_url}' 的上下文中。")

                # 关键行为触发器：如果是POST请求，立即打包分析
                if event_type == 'network_request' and event.get('method') == 'POST':
                    self.logger.info(f"检测到关键行为 (POST请求)，立即为 '{initiator_url}' 触发分析。")
                    await self.package_and_send(initiator_url)

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("上下文关联器正在关闭。")
            self.logger.info("正在处理所有剩余的上下文...")
            for initiator_url in list(self.contexts.keys()):
                await self.package_and_send(initiator_url)
        finally:
            manager_task.cancel()
            await asyncio.gather(manager_task, return_exceptions=True)