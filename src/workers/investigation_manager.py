import asyncio
import logging
from asyncio import Queue
from typing import Set, List, Dict, Any, Optional
from playwright.async_api import Browser

from src.workers.agent_worker import AgentWorker
from src.workers.interaction_worker import InteractionWorker
from src.models.shared_state import SharedState
from src.utils.browser_pool import BrowserPool
from src.tools import browser_tools, auth_tools

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
        self.investigated_urls: Set[str] = set()
        self.active_investigations: Set[str] = set()
        self.agent_tasks: List[asyncio.Task] = []
        pool_size = self.config.get('browser_pool', {}).get('pool_size', 3)
        self.browser_pool = BrowserPool(pool_size=pool_size)
        
        # 创建一个统一的并发信号量，由管理器统一控制
        self.concurrency_semaphore = asyncio.Semaphore(pool_size)
        self.logger.info(f"已创建统一并发信号量，最大并发数: {pool_size}")

        # 初始化交互分析器（用于被动模式）
        self.interaction_worker = InteractionWorker(
            config=config,
            browser_pool=self.browser_pool,
            concurrency_semaphore=self.concurrency_semaphore, # 传递信号量
            input_q=input_q,
            output_q=output_q,
            debug_events_q=debug_q
        )

    async def initialize(self, main_browser: Browser, playwright: Any, initial_auth_state: Optional[Dict] = None):
        """根据配置模式和初始认证状态，初始化浏览器池。"""
        pool_mode = self.config.get('browser_pool', {}).get('mode', 'standalone')
        self.logger.info(f"检测到浏览器池模式: '{pool_mode}'")
        
        if pool_mode == 'shared':
            await self.browser_pool.initialize_shared(main_browser, playwright)
        else:  # standalone
            # 优先使用main.py在启动时扫描到的认证状态
            await self.browser_pool.initialize_standalone(playwright, initial_auth_state, main_browser)

    async def close(self):
        """关闭所有代理任务和浏览器池。"""
        self.logger.info("正在关闭调查管理器...")
        for task in self.agent_tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*self.agent_tasks, return_exceptions=True)
        await self.browser_pool.close()
        self.logger.info("调查管理器已成功关闭。")

    def _on_investigation_complete(self, url: str):
        """当一个Agent完成调查时的回调函数。"""
        self.logger.info(f"调查完成: {url}")
        if url in self.active_investigations:
            self.active_investigations.remove(url)
        self.investigated_urls.add(url)

    async def run(self):
        self.logger.info("调查任务管理器正在运行。")
        
        # 检查执行模式
        execution_mode = self.config.get('investigation_manager', {}).get('execution_mode', 'autonomous')
        self.logger.info(f"执行模式: {execution_mode}")
        
        try:
            while True:
                event = await self.input_q.get()
                
                # 检查事件类型
                event_type = event.get('event_type', 'navigation')
                
                if event_type == 'user_interaction' and execution_mode == 'passive':
                    # 被动模式：处理用户交互事件
                    await self._handle_user_interaction(event)
                elif event_type == 'navigation':
                    # 导航事件：在所有模式下都处理
                    await self._handle_navigation_event(event, execution_mode)
                else:
                    # 其他事件类型或不匹配的模式
                    self.logger.debug(f"忽略事件: {event_type} 在模式 {execution_mode} 下")
                
                self.input_q.task_done()
        
        except asyncio.CancelledError:
            self.logger.info("调查任务管理器收到关闭信号。")
        finally:
            await asyncio.gather(*self.agent_tasks, return_exceptions=True)
    
    async def _handle_user_interaction(self, interaction_event: dict):
        """
        处理用户交互事件（被动模式）
        """
        try:
            self.logger.info(f"处理用户交互事件: {interaction_event.get('interaction_type')} 在 {interaction_event.get('url')}")
            
            # 获取当前认证状态（如果需要）
            auth_state = None
            if self.browser_pool.auth_state:
                auth_state = self.browser_pool.auth_state
            
            # 为交互事件添加认证状态
            interaction_event['auth_state'] = auth_state
            
            # 直接调用交互分析器的analyze_interaction，由其内部管理任务
            asyncio.create_task(self.interaction_worker.handle_interaction_event(interaction_event))
            
        except Exception as e:
            self.logger.error(f"处理用户交互事件时出错: {e}", exc_info=True)
    
    async def _handle_navigation_event(self, nav_info: dict, execution_mode: str):
        """
        处理导航事件（自主模式）
        """
        target_url = nav_info.get('url')
        auth_state = nav_info.get('auth_state')
        
        if not target_url or target_url in self.investigated_urls or target_url in self.active_investigations:
            if target_url:
                self.logger.info(f"目标 '{target_url}' 已完成或正在调查中，本次跳过。")
            return

        self.logger.info(f"收到新的调查目标: {target_url}")
        self.active_investigations.add(target_url)

        # 动态更新浏览器池的认证状态
        if auth_state:
            await self.browser_pool.update_auth_state(auth_state)

        goal = f"对网页 '{target_url}' 进行全面的、方法论驱动的安全审计。"
        
        # 创建自主决策模式的Agent
        agent = AgentWorker(
            goal=goal, 
            start_url=target_url, 
            auth_state=auth_state,
            config=self.config, 
            browser_pool=self.browser_pool, 
            concurrency_semaphore=self.concurrency_semaphore, # 传递信号量
            output_q=self.output_q,
            debug_events_q=self.debug_q,
            on_complete=self._on_investigation_complete
        )
        task = asyncio.create_task(agent.run(), name=f"Agent-{target_url[:30]}")
        
        self.agent_tasks.append(task)