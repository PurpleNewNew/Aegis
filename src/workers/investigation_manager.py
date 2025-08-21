import asyncio
import logging
from asyncio import Queue
from typing import Set, List, Dict, Any
from collections import defaultdict
from playwright.async_api import Browser

from src.workers.agent_worker import AgentWorker
from src.workers.interaction_worker import InteractionWorker
from src.models.shared_state import SharedState
from src.utils.browser_pool import BrowserPool
from src.tools import browser_tools

class InvestigationManager:
    """
    管理所有主动调查任务和浏览器池。它根据配置选择浏览器池模式，
    并为每个新URL分派一个AgentWorker。
    """

    def __init__(self, input_q: Queue, output_q: Queue, debug_q: Queue, config: dict):
        self.input_q = input_q
        self.output_q = output_q
        self.debug_q = debug_q
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.active_endpoints: Set[str] = set()
        self.agent_tasks: List[asyncio.Task] = []
        pool_size = self.config.get('browser_pool', {}).get('pool_size', 3)
        self.browser_pool = BrowserPool(pool_size=pool_size)
        
        self.concurrency_semaphore = asyncio.Semaphore(pool_size)
        self.logger.info(f"已创建统一并发信号量，最大并发数: {pool_size}")

        # 新增：用于存储每个URL上的交互链
        self.interaction_chains: Dict[str, List[Dict]] = defaultdict(list)

        self.interaction_worker = InteractionWorker(
            config=config,
            browser_pool=self.browser_pool,
            concurrency_semaphore=self.concurrency_semaphore,
            input_q=input_q,
            output_q=output_q,
            debug_events_q=debug_q
        )

    async def initialize(self, main_browser: Browser, playwright: Any):
        """根据配置模式，初始化浏览器池。"""
        pool_mode = self.config.get('browser_pool', {}).get('mode', 'standalone')
        self.logger.info(f"检测到浏览器池模式: '{pool_mode}'")
        
        if pool_mode == 'shared':
            await self.browser_pool.initialize_shared(main_browser, playwright)
        else:  # standalone
            auth_state = None
            if main_browser.contexts and main_browser.contexts[0].pages:
                page = main_browser.contexts[0].pages[0]
                auth_state = await page.context.storage_state()
            await self.browser_pool.initialize_standalone(playwright, auth_state)

    async def close(self):
        """关闭所有代理任务和浏览器池。"""
        self.logger.info("正在关闭调查管理器...")
        for task in self.agent_tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*self.agent_tasks, return_exceptions=True)
        await self.browser_pool.close()
        self.logger.info("调查管理器已成功关闭。")

    def _on_investigation_complete(self, endpoint: str):
        """当一个Agent完成调查时的回调函数。"""
        self.logger.info(f"端点 {endpoint} 的长期监控任务已结束。")
        if endpoint in self.active_endpoints:
            self.active_endpoints.remove(endpoint)

    async def run(self):
        self.logger.info("调查任务管理器正在运行。")
        execution_mode = self.config.get('investigation_manager', {}).get('execution_mode', 'passive')
        self.logger.info(f"执行模式: {execution_mode}")
        
        try:
            while True:
                event = await self.input_q.get()
                event_type = event.get('event_type', 'navigation')
                
                if event_type == 'user_interaction' and execution_mode == 'passive':
                    await self._handle_user_interaction(event)
                elif event_type == 'navigation':
                    await self._handle_navigation_event(event)
                else:
                    self.logger.debug(f"忽略事件: {event_type} 在模式 {execution_mode} 下")
                
                self.input_q.task_done()
        
        except asyncio.CancelledError:
            self.logger.info("调查任务管理器收到关闭信号。")
        finally:
            for task in self.agent_tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*self.agent_tasks, return_exceptions=True)
    
    def _is_commit_action(self, event: Dict[str, Any]) -> bool:
        """判断一个交互是否是“提交性操作”。"""
        interaction_type = event.get('interaction_type')
        tag = event.get('element_info', {}).get('tag', '').upper()
        
        if interaction_type == 'submit':
            return True
        if interaction_type == 'click' and tag in ['BUTTON', 'A']:
             # 简单起见，我们假设所有按钮和链接点击都是提交性操作
             # 未来可以根据按钮文本（如Save, Submit, Login）进行更精细的判断
            return True
        return False

    async def _handle_user_interaction(self, event: dict):
        """处理用户交互事件，实现交互链聚合与调度。"""
        url = event.get('url')
        if not url:
            return

        # 将当前事件追加到对应URL的操作链中
        self.interaction_chains[url].append(event)
        self.logger.info(f"记录交互事件: {event.get('interaction_type')} on {url}。当前链长度: {len(self.interaction_chains[url])}")

        # 检查当前事件是否为“提交性操作”
        if self._is_commit_action(event):
            chain_to_analyze = self.interaction_chains[url][:]
            self.logger.info(f"检测到提交性操作，派发包含 {len(chain_to_analyze)} 个事件的分析任务...")
            
            # 派发任务进行分析
            asyncio.create_task(self.interaction_worker.analyze_interaction_chain(chain_to_analyze))
            
            # 清空当前URL的操作链，为下一次逻辑操作做准备
            self.interaction_chains[url].clear()

    async def _handle_navigation_event(self, nav_info: dict):
        """
        处理导航事件，根据是否为新端点来决定分析策略。
        """
        full_url = nav_info.get('url')
        endpoint = nav_info.get('endpoint')
        is_new_endpoint = nav_info.get('is_new_endpoint', False)
        auth_state = nav_info.get('auth_state')

        if not full_url or not endpoint:
            return

        # 对所有导航事件，都进行一次URL参数分析
        asyncio.create_task(self.interaction_worker.analyze_url(nav_info))

        # 只有在新端点第一次出现时，才启动一个长期运行的AgentWorker来维持被动环境
        if is_new_endpoint and endpoint not in self.active_endpoints:
            self.logger.info(f"发现全新端点: {endpoint}，将启动长期监控Agent。")
            self.active_endpoints.add(endpoint)

            if auth_state:
                await self.browser_pool.update_auth_state(auth_state)

            goal = f"对端点 '{endpoint}' 进行被动模式下的长期监控和深度交互分析。"
            
            agent = AgentWorker(
                goal=goal, 
                start_url=full_url, 
                auth_state=auth_state,
                config=self.config, 
                browser_pool=self.browser_pool, 
                concurrency_semaphore=self.concurrency_semaphore,
                output_q=self.output_q,
                debug_events_q=self.debug_q,
                on_complete=lambda: self._on_investigation_complete(endpoint)
            )
            task = asyncio.create_task(agent.run(), name=f"PassiveAgent-{endpoint[:50]}")
            self.agent_tasks.append(task)