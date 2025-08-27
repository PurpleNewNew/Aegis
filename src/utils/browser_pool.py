import asyncio
import json
import logging
import random
import time
import os
import aiofiles
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, BrowserContext, Browser, Page, Playwright
from typing import List, Dict, Any, Optional
from collections import defaultdict

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
]

class PersistentAuthState:
    """Persistent authentication state manager"""
    
    def __init__(self, storage_dir: str = "./auth_states"):
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(exist_ok=True)
        self.domain_states = {}
        self.global_state = None
        self.logger = logging.getLogger(self.__class__.__name__)
        
    async def save_state(self, domain: str, state: Dict[str, Any]):
        """Save state for a specific domain"""
        self.domain_states[domain] = state
        
        # Persist to disk
        state_file = self.storage_dir / f"{domain.replace(':', '_').replace('/', '_')}.json"
        try:
            async with aiofiles.open(state_file, 'w', encoding='utf-8') as f:
                await f.write(json.dumps(state, ensure_ascii=False))
            self.logger.debug(f"Saved auth state for {domain}")
        except Exception as e:
            self.logger.error(f"Failed to save auth state for {domain}: {e}")
    
    async def load_state(self, domain: str) -> Optional[Dict[str, Any]]:
        """Load state for a specific domain"""
        # Check memory first
        if domain in self.domain_states:
            return self.domain_states[domain]
        
        # Check disk
        state_file = self.storage_dir / f"{domain.replace(':', '_').replace('/', '_')}.json"
        if state_file.exists():
            try:
                async with aiofiles.open(state_file, 'r', encoding='utf-8') as f:
                    state = json.loads(await f.read())
                self.domain_states[domain] = state
                self.logger.debug(f"Loaded auth state for {domain}")
                return state
            except Exception as e:
                self.logger.error(f"Failed to load auth state for {domain}: {e}")
        
        return None
    
    async def save_global_state(self, state: Dict[str, Any]):
        """Save global auth state"""
        self.global_state = state
        state_file = self.storage_dir / "global_state.json"
        try:
            async with aiofiles.open(state_file, 'w', encoding='utf-8') as f:
                await f.write(json.dumps(state, ensure_ascii=False))
        except Exception as e:
            self.logger.error(f"Failed to save global auth state: {e}")
    
    async def load_global_state(self) -> Optional[Dict[str, Any]]:
        """Load global auth state"""
        if self.global_state:
            return self.global_state
            
        state_file = self.storage_dir / "global_state.json"
        if state_file.exists():
            try:
                async with aiofiles.open(state_file, 'r', encoding='utf-8') as f:
                    self.global_state = json.loads(await f.read())
                return self.global_state
            except Exception as e:
                self.logger.error(f"Failed to load global auth state: {e}")
        
        return None
    
    def get_domain_for_url(self, url: str) -> str:
        """Extract domain from URL"""
        parsed = urlparse(url)
        return parsed.netloc

class AuthSynchronizer:
    def __init__(self, browser_pool: 'BrowserPool'):
        self.pool = browser_pool
        self.logger = logging.getLogger(self.__class__.__name__)
        self.task: Optional[asyncio.Task] = None
        self.last_sync_time = 0
        self.min_sync_interval = 1.0  # Minimum seconds between syncs

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

    async def sync_on_navigation(self, url: str):
        """Sync auth state when navigation occurs"""
        current_time = time.time()
        if current_time - self.last_sync_time < self.min_sync_interval:
            return
            
        if self.pool.main_browser and self.pool.main_browser.is_connected():
            current_auth_state = await self._get_current_main_browser_auth_state()
            if current_auth_state:
                # Save domain-specific state
                domain = self.pool.persistent_state.get_domain_for_url(url)
                await self.pool.persistent_state.save_state(domain, current_auth_state)
                
                # Sync to pool
                await self.sync_auth_state_to_pool(current_auth_state)
                self.last_sync_time = current_time

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
        
        # Update all active contexts with new state
        if self.pool.mode == 'standalone':
            async with self.pool.resource_lock:
                # Mark existing contexts for recreation
                for context_id in list(self.pool.context_usage.keys()):
                    self.pool.context_usage[context_id] = self.pool.max_usages_per_context + 1

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
        self.persistent_state = PersistentAuthState()
        
        # 健康检查相关
        self.health_check_interval = 60  # 每分钟检查一次
        self.health_check_task = None
        self.unhealthy_contexts = set()

    async def initialize_shared(self, main_browser: Browser, playwright: Playwright):
        self.mode = 'shared'
        self.main_browser = main_browser
        self.playwright = playwright
        self.logger.info(f"正在初始化共享浏览器池，大小为 {self.pool_size}...")
        main_context = main_browser.contexts[0]
        self.auth_state = await main_context.storage_state()
        
        # Save initial state
        await self.persistent_state.save_global_state(self.auth_state)
        
        for _ in range(self.pool_size):
            page = await main_context.new_page()
            await self.pool.put(ContextWrapper(page, main_context))
        self.logger.info(f"共享浏览器池初始化成功。")

    async def initialize_standalone(self, playwright: Playwright, auth_state: Optional[Dict] = None, main_browser: Optional[Browser] = None):
        self.mode = 'standalone'
        self.playwright = playwright
        self.main_browser = main_browser
        
        # Try to load persistent state if no auth_state provided
        if not auth_state:
            auth_state = await self.persistent_state.load_global_state()
            
        self.auth_state = auth_state
        self.logger.info(f"正在初始化独立浏览器池，大小为 {self.pool_size}...")
        self.browser = await self.playwright.chromium.launch(headless=True, args=['--disable-blink-features=AutomationControlled'])
        for _ in range(self.pool_size):
            await self._create_and_add_context()
        self.logger.info(f"独立浏览器池初始化成功{'(已复制认证状态)' if auth_state else ''}")
        if main_browser:
            self.auth_synchronizer = AuthSynchronizer(self)
            await self.auth_synchronizer.start()
        
        # 启动健康检查任务
        self.health_check_task = asyncio.create_task(self._health_check_loop())

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

    async def create_context_for_domain(self, url: str) -> Any:
        """Create a context with domain-specific auth state"""
        domain = self.persistent_state.get_domain_for_url(url)
        domain_state = await self.persistent_state.load_state(domain)
        
        context_options = {
            'user_agent': random.choice(USER_AGENTS),
            'viewport': {'width': 1920, 'height': 1080},
            'ignore_https_errors': True,
            'storage_state': domain_state or self.auth_state
        }
        context = await self.browser.new_context(**context_options)
        await context.add_init_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined});")
        async with self.resource_lock:
            self.context_creation_time[id(context)] = time.time()
            self.context_usage[id(context)] = 0
        return context

    async def acquire(self) -> Any:
        # 尝试获取上下文，带有重试机制
        for attempt in range(3):
            try:
                context = await asyncio.wait_for(self.pool.get(), timeout=30.0)
                
                # 健康检查
                if id(context) in self.unhealthy_contexts:
                    self.logger.warning(f"获取到不健康的上下文，正在重建...")
                    await self._recreate_context(context)
                    # 重新获取新的上下文
                    context = await asyncio.wait_for(self.pool.get(), timeout=30.0)
                
                # 验证上下文是否有效
                if not await self._is_context_healthy(context):
                    self.logger.warning(f"上下文不健康，正在重建...")
                    await self._recreate_context(context)
                    # 重新获取新的上下文
                    context = await asyncio.wait_for(self.pool.get(), timeout=30.0)
                
                async with self.resource_lock:
                    self.active_contexts.add(id(context))
                    self.context_usage[id(context)] += 1
                    
                return context
                
            except asyncio.TimeoutError:
                if attempt < 2:
                    self.logger.warning(f"获取浏览器上下文超时，重试中 ({attempt + 1}/3)...")
                    await asyncio.sleep(1)
                else:
                    raise
            except Exception as e:
                self.logger.error(f"获取浏览器上下文时出错: {e}")
                if attempt < 2:
                    await asyncio.sleep(1)
                else:
                    raise

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
                self.unhealthy_contexts.discard(context_id)

    # 健康检查相关方法
    async def _health_check_loop(self):
        """定期健康检查循环"""
        while True:
            try:
                await asyncio.sleep(self.health_check_interval)
                await self._check_all_contexts()
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"健康检查出错: {e}")
    
    async def _check_all_contexts(self):
        """检查所有上下文的健康状态"""
        if self.mode == 'shared':
            return  # 共享模式不需要健康检查
            
        contexts_to_check = []
        # 复制队列中的上下文进行检查
        temp_pool = []
        while not self.pool.empty():
            try:
                context = self.pool.get_nowait()
                contexts_to_check.append(context)
                temp_pool.append(context)
            except asyncio.QueueEmpty:
                break
        
        # 将上下文放回队列
        for context in temp_pool:
            await self.pool.put(context)
        
        # 检查每个上下文
        for context in contexts_to_check:
            if not await self._is_context_healthy(context):
                context_id = id(context)
                self.unhealthy_contexts.add(context_id)
                self.logger.warning(f"标记不健康的上下文: {context_id}")
    
    async def _is_context_healthy(self, context: Any) -> bool:
        """检查上下文是否健康"""
        try:
            # 检查上下文是否已关闭
            if hasattr(context, 'pages') and len(context.pages) > 0:
                if context.pages[0].is_closed():
                    return False
            
            # 尝试创建一个新页面作为健康检查
            if hasattr(context, 'new_page'):
                page = await context.new_page()
                try:
                    await page.goto('about:blank', timeout=5000)
                    await page.evaluate('() => 1 + 1')  # 简单的JS执行测试
                    return True
                finally:
                    if not page.is_closed():
                        await page.close()
            
            return True
        except Exception as e:
            self.logger.debug(f"健康检查失败: {e}")
            return False
    
    async def _recreate_context(self, old_context: Any):
        """重建不健康的上下文"""
        try:
            async with self.resource_lock:
                context_id = id(old_context)
                self.active_contexts.discard(context_id)
                self.context_usage.pop(context_id, None)
                self.context_creation_time.pop(context_id, None)
                self.unhealthy_contexts.discard(context_id)
            
            await self._close_context(old_context)
            await self._create_and_add_context()
            self.logger.info("已重建不健康的上下文")
        except Exception as e:
            self.logger.error(f"重建上下文失败: {e}")

    async def close(self):
        self.logger.info("正在关闭浏览器池...")
        
        # 停止健康检查任务
        if self.health_check_task and not self.health_check_task.done():
            self.health_check_task.cancel()
            try:
                await self.health_check_task
            except asyncio.CancelledError:
                pass
        
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
