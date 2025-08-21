import asyncio
import logging
import json
import aiofiles
from openai import AsyncOpenAI
from playwright.async_api import Page, BrowserContext
from typing import List, Dict, Any, Callable, Optional
from asyncio import Queue, Semaphore, Task

from src.tools.network_tools import NetworkSniffer

class AgentWorker:
    """
    Aegis的最终版"AI指挥官"代理，实现了"真登录"和"高效侦察"逻辑。
    """

    def __init__(self, goal: str, start_url: str, auth_state: Dict, config: dict, browser_pool: Any, concurrency_semaphore: Semaphore, output_q: Queue, debug_events_q: Queue, on_complete: Callable[[str], None], shared_state: Any = None):
        self.goal = goal
        self.start_url = start_url
        self.auth_state = auth_state
        self.config = config
        self.browser_pool = browser_pool
        self.concurrency_semaphore = concurrency_semaphore
        self.output_q = output_q
        self.debug_events_q = debug_events_q
        self.on_complete = on_complete
        self.logger = logging.getLogger(f"Agent({start_url[:30]}...)")
        self.max_steps = 15
        self.final_findings: List[Dict[str, Any]] = []
        self.iast_findings: List[Dict[str, Any]] = []
        self.max_parallel_interactions = self.concurrency_semaphore._value
        self._debug_listener_task: Optional[Task] = None
        self.js_hook_script = ""
        self.network_sniffer = NetworkSniffer()

        self.shared_state = shared_state
        if self.shared_state:
            self.shared_state.current_url = start_url
            self.shared_state.goal = goal
        
        llm_config = self.config['llm_service']
        self.llm_client = AsyncOpenAI(base_url=llm_config['api_config']['base_url'], api_key=llm_config['api_config']['api_key'])

    async def _load_js_hooks(self):
        try:
            async with aiofiles.open('src/tools/js_hooks.js', mode='r', encoding='utf-8') as f:
                self.js_hook_script = await f.read()
                self.logger.info("IAST JS Hook脚本加载成功。")
        except Exception as e:
            self.logger.error(f"加载IAST JS Hook脚本失败: {e}")

    async def _listen_for_debug_events(self):
        """A background task to listen for events from the CDPDebugger and IAST hooks."""
        self.logger.info("IAST/CDP事件监听器已启动。")
        try:
            while True:
                debug_event = await self.debug_events_q.get()
                self.logger.info(f"接收到IAST/CDP调试事件: {debug_event}")
                self.iast_findings.append(debug_event)
                self.debug_events_q.task_done()
        except asyncio.CancelledError:
            self.logger.info("IAST/CDP事件监听器已关闭。")

    async def run(self):
        await self._load_js_hooks()
        self._debug_listener_task = asyncio.create_task(self._listen_for_debug_events())
        try:
            async with self.concurrency_semaphore:
                self.logger.info(f"AgentWorker已获取信号量，开始执行任务。当前并发: {self.max_parallel_interactions - self.concurrency_semaphore._value}/{self.max_parallel_interactions}")
        finally:
            if self._debug_listener_task and not self._debug_listener_task.done():
                self._debug_listener_task.cancel()
    
    async def _setup_page_for_analysis(self, page: Page):
        """Exposes IAST callback and injects JS hooks for a given page."""
        if not self.js_hook_script:
            return
        try:
            await page.expose_function("__aegis_iast_report__", lambda finding: self.debug_events_q.put_nowait(finding))
            await page.add_init_script(self.js_hook_script)
            self.logger.info(f"成功为页面 {page.url} 注入IAST Hooks。")
        except Exception as e:
            self.logger.error(f"为页面 {page.url} 注入IAST Hooks失败: {e}")