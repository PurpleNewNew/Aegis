import asyncio
import json
import logging
import random
import time
from playwright.async_api import async_playwright, BrowserContext, Browser, Page, Playwright
from typing import List, Dict, Any, Optional
from collections import defaultdict

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
]

class AuthSynchronizer:
    def __init__(self, browser_pool: 'BrowserPool'):
        self.pool = browser_pool
        self.logger = logging.getLogger(self.__class__.__name__)
        self.task: Optional[asyncio.Task] = None

    async def start(self):
        if self.pool.main_browser and self.pool.main_browser.is_connected():
            self.logger.info("🤖 启动智能认证同步...")
            self.task = asyncio.create_task(self._smart_auth_sync_loop(), name="AuthSyncLoop")

    async def stop(self):
        if self.task and not self.task.done():
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                self.logger.info("认证同步任务已成功取消。")

    async def _smart_auth_sync_loop(self):
        while True:
            try:
                await asyncio.sleep(self.pool.auth_sync_interval)
                if not self.pool.main_browser or not self.pool.main_browser.is_connected():
                    self.logger.warning("主浏览器断开连接，停止认证同步")
                    break
                current_auth_state = await self._get_current_main_browser_auth_state()
                if current_auth_state and self._has_auth_state_changed(current_auth_state):
                    self.logger.info("🔄 检测到认证状态变化，正在同步...")
                    await self.sync_auth_state_to_pool(current_auth_state)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"智能认证同步出错: {e}")
                await asyncio.sleep(10)

    async def _get_current_main_browser_auth_state(self) -> Optional[Dict[str, Any]]:
        try:
            return await self.pool.main_browser.contexts[0].storage_state()
        except Exception as e:
            # This can happen during shutdown, so we log at a lower level
            if "closed" in str(e).lower():
                self.logger.debug(f"获取主浏览器认证状态失败，连接已关闭: {e}")
            else:
                self.logger.error(f"获取主浏览器认证状态失败: {e}")
            return None

    def _has_auth_state_changed(self, current_state: Dict[str, Any]) -> bool:
        if not self.pool.auth_state: return True
        return json.dumps(self.pool.auth_state, sort_keys=True) != json.dumps(current_state, sort_keys=True)

    async def sync_auth_state_to_pool(self, new_auth_state: Dict[str, Any]):
        self.logger.info(f"向浏览器池广播新的认证状态...")
        self.pool.auth_state = new_auth_state

class BrowserPool:
    def __init__(self, pool_size: int = 5, periodic_sync_interval: int = 30):
        self.pool_size = pool_size
        self.pool: asyncio.Queue = asyncio.Queue(maxsize=pool_size)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.playwright: Optional[Playwright] = None
        self.browser: Optional[Browser] = None
        self.mode: Optional[str] = None
        self.auth_state: Optional[Dict] = None
        self.main_browser: Optional[Browser] = None
        self.auth_sync_interval = periodic_sync_interval
        self.active_contexts = set()
        self.context_usage = defaultdict(int)
        self.context_creation_time = {}
        self.max_context_lifetime = 600
        self.max_usages_per_context = 20
        self.resource_lock = asyncio.Lock()
        self.auth_synchronizer: Optional[AuthSynchronizer] = None

    async def initialize_shared(self, main_browser: Browser, playwright: Playwright):
        self.mode = 'shared'
        self.main_browser = main_browser
        self.playwright = playwright
        self.logger.info(f"正在初始化共享浏览器池，大小为 {self.pool_size}...")
        main_context = main_browser.contexts[0]
        self.auth_state = await main_context.storage_state()
        for _ in range(self.pool_size):
            page = await main_context.new_page()
            await self.pool.put(ContextWrapper(page, main_context))
        self.logger.info(f"共享浏览器池初始化成功。")

    async def initialize_standalone(self, playwright: Playwright, auth_state: Optional[Dict] = None, main_browser: Optional[Browser] = None):
        self.mode = 'standalone'
        self.playwright = playwright
        self.auth_state = auth_state
        self.main_browser = main_browser
        self.logger.info(f"正在初始化独立浏览器池，大小为 {self.pool_size}...")
        self.browser = await self.playwright.chromium.launch(headless=True, args=['--disable-blink-features=AutomationControlled'])
        for _ in range(self.pool_size):
            await self._create_and_add_context()
        self.logger.info(f"独立浏览器池初始化成功{'(已复制认证状态)' if auth_state else ''}")
        if main_browser:
            self.auth_synchronizer = AuthSynchronizer(self)
            await self.auth_synchronizer.start()

    async def update_auth_state(self, new_state: Dict[str, Any]):
        if self.mode == 'shared': return
        async with self.resource_lock:
            self.logger.info("接收到新的导航事件，正在更新浏览器池的认证状态...")
            self.auth_state = new_state
            self.logger.info("浏览器池认证状态已更新。新创建的浏览器将使用此状态。")

    async def _create_and_add_context(self):
        context_options = {
            'user_agent': random.choice(USER_AGENTS),
            'viewport': {'width': 1920, 'height': 1080},
            'ignore_https_errors': True,
            'storage_state': self.auth_state
        }
        context = await self.browser.new_context(**context_options)
        await context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined});")
        async with self.resource_lock:
            self.context_creation_time[id(context)] = time.time()
            self.context_usage[id(context)] = 0
        await self.pool.put(context)

    async def acquire(self) -> Any:
        context = await asyncio.wait_for(self.pool.get(), timeout=30.0)
        async with self.resource_lock:
            self.active_contexts.add(id(context))
            self.context_usage[id(context)] += 1
        return context

    async def release(self, context: Any):
        try:
            if await self._should_recreate(context):
                await self._close_context(context)
                await self._create_and_add_context()
            else:
                await self._cleanup_context(context)
                await self.pool.put(context)
        except Exception as e:
            self.logger.error(f"归还浏览器上下文失败: {e}")
            async with self.resource_lock:
                self.active_contexts.discard(id(context))

    async def _should_recreate(self, context: Any) -> bool:
        async with self.resource_lock:
            context_id = id(context)
            usage = self.context_usage.get(context_id, 0)
            creation_time = self.context_creation_time.get(context_id, 0)
            if usage > self.max_usages_per_context:
                self.logger.info(f"Context使用次数过多({usage})，将重建")
                return True
            if time.time() - creation_time > self.max_context_lifetime:
                self.logger.info(f"Context存活时间过长({time.time() - creation_time:.0f}秒)，将重建")
                return True
        return False

    async def _cleanup_context(self, context: Any):
        if self.mode == 'shared':
            wrapper = context
            for page in wrapper.pages[1:]:
                if not page.is_closed(): await page.close()
            wrapper.pages = wrapper.pages[:1]
            if wrapper.pages and not wrapper.pages[0].is_closed():
                await wrapper.pages[0].goto('about:blank')
        else:
            for page in context.pages:
                if not page.is_closed(): await page.close()
            await context.clear_permissions()
            await context.new_page()

    async def _close_context(self, context: Any):
        try:
            await context.close()
        except Exception as e:
            if "closed" not in str(e).lower():
                self.logger.error(f"关闭context时发生意外错误: {e}")
        finally:
            async with self.resource_lock:
                context_id = id(context)
                self.active_contexts.discard(context_id)
                self.context_usage.pop(context_id, None)
                self.context_creation_time.pop(context_id, None)

    async def close(self):
        self.logger.info("正在关闭浏览器池...")
        if self.auth_synchronizer:
            await self.auth_synchronizer.stop()
        
        while not self.pool.empty():
            try:
                context = self.pool.get_nowait()
                await self._close_context(context)
            except asyncio.QueueEmpty:
                break
        if self.mode == 'standalone' and self.browser and self.browser.is_connected():
            await self.browser.close()
        self.logger.info("浏览器池已安全关闭。")

class ContextWrapper:
    def __init__(self, page: Page, context: BrowserContext):
        self.pages = [page]
        self.context = context
        self._page = page

    def __getattr__(self, name):
        if hasattr(self._page, name):
            return getattr(self._page, name)
        return getattr(self.context, name)

    async def new_page(self) -> Page:
        return self._page

    async def close(self):
        if not self._page.is_closed():
            await self._page.close()