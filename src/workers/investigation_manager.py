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
        
        # 根据执行模式确定浏览器池大小
        execution_mode = self.config.get('investigation_manager', {}).get('execution_mode', 'passive')
        browser_config = self.config.get('browser_pool', {})
        
        if execution_mode == 'passive':
            pool_size = browser_config.get('passive_mode_pool_size', 1)
        else:  # autonomous/active mode
            pool_size = browser_config.get('active_mode_pool_size', 
                                        browser_config.get('pool_size', 5))
        
        self.browser_pool = BrowserPool(pool_size=pool_size)
        self.execution_mode = execution_mode
        
        self.concurrency_semaphore = asyncio.Semaphore(pool_size)
        self.logger.info(f"已创建统一并发信号量，最大并发数: {pool_size} (模式: {execution_mode})")

        # 新增：用于存储每个URL上的交互链（带内存管理）
        self.interaction_chains: Dict[str, List[Dict]] = defaultdict(list)
        self.interaction_chain_timestamps: Dict[str, float] = {}  # 记录每个URL最后访问时间
        self.max_chain_age = 1800  # 30分钟后自动清理（秒）
        self.max_chains = 100      # 最大保存的URL数量
        self.max_chain_length = 50 # 每个URL最大交互事件数
        self.chain_cleanup_task = None
        
        # 导入交互序列管理器
        from src.utils.interaction_sequence_manager import InteractionSequenceManager
        self.sequence_manager = InteractionSequenceManager()

        self.interaction_worker = InteractionWorker(
            config=config,
            browser_pool=self.browser_pool,
            concurrency_semaphore=self.concurrency_semaphore,
            input_q=input_q,
            output_q=output_q,
            debug_events_q=debug_q
        )
        
        # 启动定期清理任务
        self.chain_cleanup_task = asyncio.create_task(self._periodic_chain_cleanup())
        self.logger.info(f"已启用交互链内存管理：最大URL数={self.max_chains}, 最大链长={self.max_chain_length}, 清理间隔={self.max_chain_age}秒")

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
        
        # 取消定期清理任务
        if self.chain_cleanup_task and not self.chain_cleanup_task.done():
            self.chain_cleanup_task.cancel()
            try:
                await self.chain_cleanup_task
            except asyncio.CancelledError:
                pass
        
        # 取消所有代理任务
        for task in self.agent_tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*self.agent_tasks, return_exceptions=True)
        
        # 清理所有交互链
        self.interaction_chains.clear()
        self.interaction_chain_timestamps.clear()
        
        # 关闭浏览器池
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
        
        self.previous_interaction_url: str | None = None

        try:
            while True:
                event = await self.input_q.get()
                event_type = event.get('event_type')

                if event_type == 'user_interaction' and execution_mode == 'passive':
                    await self._handle_user_interaction(event)
                elif event_type == 'interaction_sequence' and execution_mode == 'passive':
                    await self._handle_interaction_sequence(event)
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
        """一个操作是否是“提交性”的，即是否触发了网络请求。"""
        return event.get('triggers_network_request', False)

    async def _handle_user_interaction(self, event: dict):
        """处理用户交互事件，实现交互链聚合与调度。"""
        url = event.get('url')
        if not url:
            return

        # 记录交互事件，并更新最近交互的URL
        self.interaction_chains[url].append(event)
        self.interaction_chain_timestamps[url] = asyncio.get_event_loop().time()
        self.previous_interaction_url = url
        
        # 限制每个URL的交互链长度
        if len(self.interaction_chains[url]) > self.max_chain_length:
            self.interaction_chains[url] = self.interaction_chains[url][-self.max_chain_length:]
            self.logger.debug(f"截断交互链: {url} (长度: {len(self.interaction_chains[url])})")
        
        self.logger.info(f"记录交互事件: {event.get('interaction_type')} on {url}。当前链长度: {len(self.interaction_chains[url])}")
        
        # 检查是否需要清理过多的URL
        if len(self.interaction_chains) > self.max_chains:
            await self._cleanup_oldest_chains()

        # 检查当前事件是否为“提交性操作”
        if self._is_commit_action(event):
            chain_to_analyze = self.interaction_chains[url][:]
            self.logger.info(f"检测到提交性操作，派发包含 {len(chain_to_analyze)} 个事件的分析任务...")
            
            # 派发任务进行分析，但不再清除交互链
            asyncio.create_task(self.interaction_worker.analyze_interaction_chain(chain_to_analyze))

    async def _handle_interaction_sequence(self, event: dict):
        """处理完整的交互序列事件"""
        url = event.get('url')
        sequence = event.get('sequence', [])
        sequence_type = event.get('sequence_type', 'partial')
        
        if not url or not sequence:
            return
        
        self.logger.info(f"接收到交互序列 ({sequence_type}): {len(sequence)} 个操作 on {url}")
        
        # 将交互添加到序列管理器
        for interaction in sequence:
            self.sequence_manager.add_interaction(url, interaction)
        
        # 如果是完整的序列或包含提交操作，立即分析
        if sequence_type == 'complete' or self._contains_commit_action(sequence):
            # 获取完整的执行顺序
            execution_order = self.sequence_manager.get_execution_order(url)
            
            self.logger.info(f"派发完整的交互序列进行分析，包含 {len(execution_order)} 个操作")
            asyncio.create_task(self.interaction_worker.analyze_interaction_sequence({
                'url': url,
                'sequence': execution_order,
                'auth_state': event.get('auth_state')
            }))
    
    def _contains_commit_action(self, sequence: List[Dict]) -> bool:
        """检查序列是否包含提交操作"""
        for interaction in sequence:
            interaction_type = interaction.get('type')
            if interaction_type in ['submit', 'click'] and interaction.get('details', {}).get('triggers_network_request'):
                return True
        return False

    async def _handle_navigation_event(self, nav_info: dict):
        """
        处理导航事件。导航事件也负责清理上一页的交互链。
        修复了导航与交互处理的竞态条件。
        """
        full_url = nav_info.get('url')
        endpoint = nav_info.get('endpoint')
        is_new_endpoint = nav_info.get('is_new_endpoint', False)
        auth_state = nav_info.get('auth_state')

        if not full_url or not endpoint:
            return

        # 步骤1: 同步认证状态（在清理之前）
        if auth_state and self.browser_pool.auth_synchronizer:
            await self.browser_pool.auth_synchronizer.sync_on_navigation(full_url)

        # 步骤2: 对所有导航事件，都进行一次URL参数分析
        asyncio.create_task(self.interaction_worker.analyze_url(nav_info))

        # 步骤3: 延迟清理交互链，避免与正在进行的交互分析冲突
        if self.previous_interaction_url and self.previous_interaction_url != full_url:
            # 使用异步任务延迟清理，给正在进行的交互分析时间完成
            asyncio.create_task(self._delayed_clear_interaction_chain(self.previous_interaction_url))
            self.previous_interaction_url = full_url
        elif not self.previous_interaction_url:
            self.previous_interaction_url = full_url

        # 步骤4: 只有在新端点第一次出现时，才启动一个长期运行的AgentWorker
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

    async def _delayed_clear_interaction_chain(self, url: str, delay: float = 2.0):
        """延迟清理交互链，避免与正在进行的交互分析冲突"""
        await asyncio.sleep(delay)
        if url in self.interaction_chains:
            self.logger.info(f"延迟清理URL '{url}' 的交互链。")
            self.interaction_chains[url].clear()
            # 如果链为空，延迟删除以避免频繁重建
            asyncio.create_task(self._delayed_remove_empty_chain(url))
    
    async def _delayed_remove_empty_chain(self, url: str, delay: float = 300.0):
        """延迟删除空的交互链"""
        await asyncio.sleep(delay)
        if url in self.interaction_chains and len(self.interaction_chains[url]) == 0:
            del self.interaction_chains[url]
            if url in self.interaction_chain_timestamps:
                del self.interaction_chain_timestamps[url]
            self.logger.debug(f"已删除空的交互链: {url}")
    
    async def _periodic_chain_cleanup(self):
        """定期清理过期的交互链"""
        while True:
            try:
                await asyncio.sleep(300)  # 每5分钟检查一次（更频繁的清理）
                await self._cleanup_expired_chains()
                # 强制垃圾回收
                import gc
                gc.collect()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"定期清理交互链时出错: {e}")
    
    async def _cleanup_expired_chains(self):
        """清理过期的交互链"""
        current_time = asyncio.get_event_loop().time()
        expired_urls = []
        
        for url, timestamp in self.interaction_chain_timestamps.items():
            if current_time - timestamp > self.max_chain_age:
                expired_urls.append(url)
        
        # 记录清理统计
        total_chains_before = len(self.interaction_chains)
        total_events_before = sum(len(chain) for chain in self.interaction_chains.values())
        
        for url in expired_urls:
            if url in self.interaction_chains:
                chain_length = len(self.interaction_chains[url])
                del self.interaction_chains[url]
                del self.interaction_chain_timestamps[url]
                self.logger.debug(f"清理过期交互链: {url} (长度: {chain_length})")
        
        if expired_urls:
            total_chains_after = len(self.interaction_chains)
            total_events_after = sum(len(chain) for chain in self.interaction_chains.values())
            self.logger.info(f"已清理 {len(expired_urls)} 个过期交互链，释放 {total_events_before - total_events_after} 个事件。当前: {total_chains_after} 链, {total_events_after} 事件")
    
    async def _cleanup_oldest_chains(self):
        """清理最旧的交互链（LRU策略）"""
        if len(self.interaction_chains) <= self.max_chains:
            return
        
        # 按时间戳排序，删除最旧的20%
        sorted_urls = sorted(self.interaction_chain_timestamps.items(), key=lambda x: x[1])
        urls_to_remove = sorted_urls[:int(self.max_chains * 0.2)]
        
        for url, _ in urls_to_remove:
            if url in self.interaction_chains:
                chain_length = len(self.interaction_chains[url])
                del self.interaction_chains[url]
                del self.interaction_chain_timestamps[url]
                self.logger.info(f"LRU清理交互链: {url} (长度: {chain_length})")
        
        self.logger.info(f"LRU清理完成，当前交互链数量: {len(self.interaction_chains)}")