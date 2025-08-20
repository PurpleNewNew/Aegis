import asyncio
import json
import logging
import random
import time
from playwright.async_api import async_playwright, BrowserContext, Browser, Page, Playwright
from typing import List, Dict, Any, Optional
from collections import defaultdict

# 一组常见的、真实的User-Agent，用于随机化
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/114.0",
]

class AuthSynchronizer:
    """
    辅助类，专门负责处理独立模式下的认证状态同步，让其具备共享模式的实时性优势。
    """
    def __init__(self, browser_pool: 'BrowserPool'):
        self.pool = browser_pool
        self.logger = logging.getLogger(self.__class__.__name__)

    async def start(self):
        if self.pool.main_browser and self.pool.main_browser.is_connected():
            self.logger.info("🤖 启动智能认证同步，现在standalone模式具备shared模式的优势！")
            asyncio.create_task(self._smart_auth_sync_loop(), name="AuthSyncLoop")
            await self._setup_auth_change_listeners()

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
                    await self._sync_auth_state_to_standalone(current_auth_state)
                    self.pool.auth_state = current_auth_state
                    self.logger.info("✅ 认证状态同步完成")
            except asyncio.CancelledError:
                self.logger.info("认证同步任务被取消。")
                break
            except Exception as e:
                self.logger.error(f"智能认证同步出错: {e}")
                await asyncio.sleep(10)

    async def _get_current_main_browser_auth_state(self) -> Optional[Dict[str, Any]]:
        try:
            main_context = self.pool.main_browser.contexts[0]
            return await main_context.storage_state()
        except Exception as e:
            self.logger.error(f"获取主浏览器认证状态失败: {e}")
            return None

    def _has_auth_state_changed(self, current_state: Dict[str, Any]) -> bool:
        if not self.pool.auth_state:
            return True
        # A simple but effective way to check for changes is to compare the JSON strings
        return json.dumps(self.pool.auth_state, sort_keys=True) != json.dumps(current_state, sort_keys=True)

    async def _sync_auth_state_to_standalone(self, new_auth_state: Dict[str, Any]):
        contexts_to_sync = []
        while not self.pool.pool.empty():
            try:
                contexts_to_sync.append(await self.pool.pool.get_nowait())
            except asyncio.QueueEmpty:
                break
        
        for ctx in contexts_to_sync:
            try:
                await ctx.clear_cookies()
                await ctx.add_cookies(new_auth_state.get('cookies', []))
                # Note: localStorage and sessionStorage are part of the context state and will be handled on creation
            except Exception as e:
                self.logger.warning(f"同步单个context时出错: {e}")
            finally:
                await self.pool.pool.put(ctx)
        self.logger.info(f"成功同步认证状态到 {len(contexts_to_sync)} 个context")

    async def _setup_auth_change_listeners(self):
        # This is a simplified version. Real-time listening is complex and better handled by periodic checks.
        self.logger.info("将通过定时检查来同步认证状态。")

class BrowserPool:
    """
    管理一个Playwright浏览器上下文池，支持两种模式：
    1. 共享模式：在主浏览器中创建新标签页（共享认证状态）
    2. 独立模式：创建独立的浏览器实例（可复制认证状态）
    """
    def __init__(self, pool_size: int = 5, realtime_check_interval: int = 2, periodic_sync_interval: int = 30):
        self.pool_size = pool_size
        self.pool: asyncio.Queue = asyncio.Queue(maxsize=pool_size)
        self.logger = logging.getLogger(self.__class__.__name__)
        self.playwright = None
        self.browser = None
        self.mode = None
        self.auth_state = None
        self.main_browser = None
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
            asyncio.create_task(self.auth_synchronizer.start(), name="AuthSynchronizer")

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
        self.logger.debug(f"获取浏览器上下文，剩余可用: {self.pool.qsize()}，活跃数: {len(self.active_contexts)}")
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
            # Ensure the context is removed from active set on error
            async with self.resource_lock:
                self.active_contexts.discard(id(context))

    async def _should_recreate(self, context: Any) -> bool:
        """Checks if a context should be recreated based on age or usage."""
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
            await context.new_page() # Ensure there is always one page

    async def _close_context(self, context: Any):
        try:
            await context.close()
        except Exception as e:
            if "closed" not in str(e):
                self.logger.error(f"关闭context时发生意外错误: {e}")
        finally:
            async with self.resource_lock:
                context_id = id(context)
                self.active_contexts.discard(context_id)
                self.context_usage.pop(context_id, None)
                self.context_creation_time.pop(context_id, None)

    async def close(self):
        self.logger.info("正在关闭浏览器池...")
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
    """
    包装器类，让共享模式的页面看起来像一个context
    """
    def __init__(self, page: Page, context: BrowserContext):
        self.pages = [page]
        self.context = context
        self._page = page

    def __getattr__(self, name):
        # Prioritize page attributes, then fall back to context
        if hasattr(self._page, name):
            return getattr(self._page, name)
        return getattr(self.context, name)

    async def new_page(self) -> Page:
        return self._page

    async def close(self):
        if not self._page.is_closed():
            await self._page.close()