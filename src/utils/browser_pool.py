
import asyncio
import logging
import random
import time
from playwright.async_api import async_playwright, BrowserContext, Browser, Page
from typing import List, Dict, Any, Optional
from collections import defaultdict

# 一组常见的、真实的User-Agent，用于随机化
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/114.0",
]

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
        self.mode = None  # 'shared' or 'standalone'
        self.auth_state = None  # 存储认证状态
        self.main_browser = None  # 主浏览器引用
        
        # 资源管理和监控
        self.active_contexts = set()  # 活跃的context集合
        self.context_usage = defaultdict(int)  # context使用计数
        self.context_creation_time = {}  # context创建时间
        self.max_context_lifetime = 600  # context最大生命周期（秒）
        self.cleanup_task = None  # 清理任务
        self.resource_lock = asyncio.Lock()  # 资源操作锁
        
        # 增强功能：实时认证同步（可配置参数）
        self.auth_sync_task = None  # 认证状态同步任务
        self.last_auth_sync = 0  # 上次同步时间
        self.auth_sync_interval = periodic_sync_interval  # 定时同步间隔（秒）
        self.realtime_check_interval = realtime_check_interval  # 实时检查间隔（秒）
        self.auth_change_detected = False  # 认证变化检测标志
        self.realtime_sync_event = asyncio.Event()  # 实时同步事件

    async def initialize(self):
        """默认初始化（独立模式）"""
        await self.initialize_standalone()
        # 启动资源清理任务
        self.cleanup_task = asyncio.create_task(self._resource_cleanup_loop())
    
    async def initialize_shared(self, main_browser: Browser):
        """共享模式：在主浏览器中创建新页面"""
        self.mode = 'shared'
        self.main_browser = main_browser
        self.logger.info(f"正在初始化共享浏览器池，大小为 {self.pool_size}...")
        
        try:
            self.playwright = await async_playwright().start()
            
            # 使用主浏览器的context
            main_context = main_browser.contexts[0]
            
            # 获取并保存认证状态
            self.auth_state = await main_context.storage_state()
            
            # 创建共享页面池
            for _ in range(self.pool_size):
                # 在同一个context中创建新页面，自动共享所有状态
                page = await main_context.new_page()
                
                # 包装成ContextWrapper以保持接口一致
                wrapper = ContextWrapper(page, main_context)
                await self.pool.put(wrapper)
            
            self.logger.info(f"共享浏览器池初始化成功，创建了 {self.pool_size} 个共享认证的页面")
        except Exception as e:
            self.logger.error(f"共享浏览器池初始化失败: {e}", exc_info=True)
            # 降级到独立模式
            self.logger.info("降级到独立模式")
            await self.initialize_standalone(self.auth_state)
    
    async def initialize_standalone(self, playwright: Any, auth_state: Optional[Dict[str, Any]] = None, main_browser: Optional[Browser] = None):
        """独立模式：创建独立实例但复制认证状态，支持实时同步"""
        self.mode = 'standalone'
        self.playwright = playwright
        self.auth_state = auth_state
        self.main_browser = main_browser  # 保存主浏览器引用用于同步
        self.logger.info(f"正在初始化增强版独立浏览器池，大小为 {self.pool_size}...")
        
        try:
            # 创建独立的浏览器实例
            self.browser = await self.playwright.chromium.launch(
                headless=True,
                args=['--disable-blink-features=AutomationControlled']  # 反反爬
            )
            
            for _ in range(self.pool_size):
                # 创建context时复制认证状态
                context_options = {
                    'user_agent': random.choice(USER_AGENTS),
                    'viewport': {'width': 1920, 'height': 1080},
                    'ignore_https_errors': True,
                }
                
                # 如果有认证状态，添加到context选项中
                if self.auth_state and 'storage_state' in self.auth_state:
                    context_options['storage_state'] = self.auth_state['storage_state']
                elif self.auth_state:
                    context_options['storage_state'] = self.auth_state
                
                context = await self.browser.new_context(**context_options)
                
                # 添加反检测措施
                await context.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => undefined
                    });
                """)
                
                await self.pool.put(context)
            
            self.logger.info(f"独立浏览器池初始化成功{'(已复制认证状态)' if self.auth_state else ''}")
            
            # 如果有主浏览器，启动智能认证同步
            if self.main_browser and self.main_browser.is_connected():
                self.auth_sync_task = asyncio.create_task(self._smart_auth_sync_loop())
                self.logger.info("🤖 启动智能认证同步，现在standalone模式具备shared模式的优势！")
                
                # 给主浏览器添加认证变化监听器
                await self._setup_auth_change_listeners()
                self.logger.info("👁️ 添加了实时认证状态变化监听器")
                
        except Exception as e:
            self.logger.error(f"独立浏览器池初始化失败: {e}", exc_info=True)

    async def acquire(self) -> Any:
        """从池中获取一个浏览器上下文或包装器。"""
        try:
            # 使用超时避免无限等待
            context = await asyncio.wait_for(self.pool.get(), timeout=30.0)
            
            async with self.resource_lock:
                self.active_contexts.add(id(context))
                self.context_usage[id(context)] += 1
            
            self.logger.debug(f"获取浏览器上下文，剩余可用: {self.pool.qsize()}，活跃数: {len(self.active_contexts)}")
            return context
        except asyncio.TimeoutError:
            self.logger.error("获取浏览器上下文超时")
            raise RuntimeError("无法获取可用的浏览器上下文")

    async def release(self, context: Any):
        """将一个浏览器上下文归还到池中。"""
        try:
            async with self.resource_lock:
                context_id = id(context)
                if context_id in self.active_contexts:
                    self.active_contexts.remove(context_id)
            
            # 检查context是否需要重建（使用次数过多或时间过长）
            should_recreate = False
            if context_id in self.context_usage:
                usage_count = self.context_usage[context_id]
                if usage_count > 10:  # 使用超过10次后重建
                    should_recreate = True
                    self.logger.info(f"Context使用次数过多({usage_count})，将重建")
            
            if context_id in self.context_creation_time:
                age = time.time() - self.context_creation_time[context_id]
                if age > self.max_context_lifetime:
                    should_recreate = True
                    self.logger.info(f"Context存活时间过长({age:.0f}秒)，将重建")
            
            if should_recreate:
                # 关闭旧context并创建新的
                await self._close_context(context)
                await self._create_replacement_context()
            else:
                # 清理并归还
                if self.mode == 'shared':
                    # 共享模式：只需要关闭多余的页面
                    wrapper = context
                    # 保留一个空白页面
                    for page in wrapper.pages[1:]:
                        await page.close()
                    wrapper.pages = wrapper.pages[:1]
                    
                    # 导航到空白页
                    if wrapper.pages:
                        await wrapper.pages[0].goto('about:blank')
                else:
                    # 独立模式：完整清理context
                    for page in context.pages:
                        # Page对象没有remove_all_listeners方法，直接关闭页面
                        await page.close()
                    
                    # 不清除cookies，保持认证状态
                    await context.clear_permissions()
                    
                    # 创建新页面
                    await context.new_page()
                
                await self.pool.put(context)
                self.logger.debug(f"归还浏览器上下文，当前可用: {self.pool.qsize() + 1}")
        except Exception as e:
            self.logger.error(f"归还浏览器上下文失败: {e}")
            # 不再自动创建替代context，避免资源泄漏
            async with self.resource_lock:
                if id(context) in self.active_contexts:
                    self.active_contexts.remove(id(context))
    
    async def _create_replacement_context(self):
        """创建替代的context"""
        try:
            # 检查是否已达到池大小限制
            if self.pool.qsize() >= self.pool_size:
                self.logger.warning("浏览器池已满，不创建替代context")
                return
            
            new_context = None
            if self.mode == 'shared':
                main_context = self.main_browser.contexts[0]
                page = await main_context.new_page()
                new_context = ContextWrapper(page, main_context)
            else:
                context_options = {
                    'user_agent': random.choice(USER_AGENTS),
                    'viewport': {'width': 1920, 'height': 1080},
                    'ignore_https_errors': True,
                }
                if self.auth_state:
                    if 'storage_state' in self.auth_state:
                        context_options['storage_state'] = self.auth_state['storage_state']
                    else:
                        context_options['storage_state'] = self.auth_state
                
                new_context = await self.browser.new_context(**context_options)
                
                # 添加反检测措施
                await new_context.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => undefined
                    });
                """)
            
            if new_context:
                # 记录创建时间
                async with self.resource_lock:
                    self.context_creation_time[id(new_context)] = time.time()
                    self.context_usage[id(new_context)] = 0
                
                await self.pool.put(new_context)
                self.logger.info("成功创建替代的浏览器上下文")
        except Exception as e:
            self.logger.error(f"创建替代context失败: {e}")
    
    async def update_auth_state(self, new_state: Dict[str, Any]):
        """更新认证状态（用于动态更新）"""
        async with self.resource_lock:
            old_state = self.auth_state
            self.auth_state = new_state
            
            # 如果是共享模式，不需要更新（自动共享）
            if self.mode == 'shared':
                self.logger.debug("共享模式下认证状态自动同步")
                return
            
            # 独立模式：更新所有现有context的认证状态
            if self.mode == 'standalone' and new_state != old_state:
                self.logger.info("正在更新所有浏览器上下文的认证状态...")
                
                # 获取所有context并更新
                contexts_to_update = []
                while not self.pool.empty():
                    try:
                        ctx = await asyncio.wait_for(self.pool.get(), timeout=0.1)
                        contexts_to_update.append(ctx)
                    except asyncio.TimeoutError:
                        break
                
                # 更新每个context的cookies
                for ctx in contexts_to_update:
                    try:
                        if 'cookies' in new_state:
                            await ctx.add_cookies(new_state['cookies'])
                        # 注意：localStorage和sessionStorage不能直接设置，需要通过页面脚本
                    except Exception as e:
                        self.logger.warning(f"更新context认证状态失败: {e}")
                
                # 将context放回池中
                for ctx in contexts_to_update:
                    await self.pool.put(ctx)
                
                self.logger.info(f"已更新 {len(contexts_to_update)} 个浏览器上下文的认证状态")

    async def _close_context(self, context: Any):
        """安全地关闭一个context"""
        try:
            if self.mode == 'shared':
                wrapper = context
                for page in wrapper.pages:
                    if not page.is_closed():
                        await page.close()
            else:
                if hasattr(context, 'close'):
                    await context.close()
        except Exception as e:
            if "Target page, context or browser has been closed" in str(e):
                self.logger.debug(f"尝试关闭一个已关闭的context，此为正常现象，已忽略。")
            else:
                self.logger.error(f"关闭context时发生意外错误: {e}")
    
    async def _resource_cleanup_loop(self):
        """定期清理过期的资源"""
        while True:
            try:
                await asyncio.sleep(60)  # 每分钟检查一次
                
                async with self.resource_lock:
                    # 清理过期的使用记录
                    current_time = time.time()
                    expired_contexts = []
                    for ctx_id, creation_time in list(self.context_creation_time.items()):
                        if current_time - creation_time > self.max_context_lifetime * 2:
                            expired_contexts.append(ctx_id)
                    
                    for ctx_id in expired_contexts:
                        del self.context_creation_time[ctx_id]
                        if ctx_id in self.context_usage:
                            del self.context_usage[ctx_id]
                    
                    if expired_contexts:
                        self.logger.info(f"清理了 {len(expired_contexts)} 个过期的context记录")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"资源清理循环出错: {e}")
    
    async def _smart_auth_sync_loop(self):
        """
        智能认证状态同步循环：让standalone模式具备shared模式的优势
        - 定时检查主浏览器的认证状态变化
        - 智能检测 token 刷新、cookie 更新等
        - 自动同步到独立浏览器
        """
        self.logger.info("智能认证同步系统已启动")
        
        while True:
            try:
                await asyncio.sleep(self.auth_sync_interval)
                
                # 检查主浏览器是否仍在连接
                if not self.main_browser or not self.main_browser.is_connected():
                    self.logger.warning("主浏览器断开连接，停止认证同步")
                    break
                
                # 获取当前主浏览器的认证状态
                current_auth_state = await self._get_current_main_browser_auth_state()
                
                if current_auth_state and self._has_auth_state_changed(current_auth_state):
                    self.logger.info("🔄 检测到认证状态变化，正在同步...") 
                    
                    # 同步到独立浏览器
                    await self._sync_auth_state_to_standalone(current_auth_state)
                    
                    # 更新内部状态
                    self.auth_state = current_auth_state
                    self.last_auth_sync = time.time()
                    
                    self.logger.info("✅ 认证状态同步完成")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"智能认证同步出错: {e}")
                # 出错后稍微等待再重试
                await asyncio.sleep(10)
    
    async def _get_current_main_browser_auth_state(self) -> Optional[Dict[str, Any]]:
        """获取主浏览器的当前认证状态"""
        try:
            if not self.main_browser.contexts:
                return None
                
            main_context = self.main_browser.contexts[0]
            if not main_context.pages:
                return None
            
            # 获取存储状态（包括Cookies, localStorage, sessionStorage）
            storage_state = await main_context.storage_state()
            
            # 获取更详细的认证信息
            page = main_context.pages[0]
            enhanced_auth = await page.evaluate("""
                () => {
                    const auth_info = {};
                    
                    // 获取 localStorage
                    const ls = {};
                    try {
                        for (let i = 0; i < localStorage.length; i++) {
                            const key = localStorage.key(i);
                            ls[key] = localStorage.getItem(key);
                        }
                        auth_info.localStorage = ls;
                    } catch (e) { auth_info.localStorage = {}; }
                    
                    // 获取 sessionStorage
                    const ss = {};
                    try {
                        for (let i = 0; i < sessionStorage.length; i++) {
                            const key = sessionStorage.key(i);
                            ss[key] = sessionStorage.getItem(key);
                        }
                        auth_info.sessionStorage = ss;
                    } catch (e) { auth_info.sessionStorage = {}; }
                    
                    // 检测 JWT token
                    const jwt_patterns = ['token', 'jwt', 'access_token', 'auth_token', 'bearer'];
                    auth_info.jwt_tokens = {};
                    
                    for (const [key, value] of Object.entries({...ls, ...ss})) {
                        const lower_key = key.toLowerCase();
                        if (jwt_patterns.some(pattern => lower_key.includes(pattern))) {
                            // 简单检查是否像JWT格式
                            if (typeof value === 'string' && value.split('.').length === 3) {
                                auth_info.jwt_tokens[key] = {
                                    value: value.substring(0, 50) + '...', // 截取前50个字符
                                    full_length: value.length,
                                    looks_like_jwt: true
                                };
                            } else {
                                auth_info.jwt_tokens[key] = {
                                    value: String(value).substring(0, 50),
                                    full_length: String(value).length,
                                    looks_like_jwt: false
                                };
                            }
                        }
                    }
                    
                    return auth_info;
                }
            """)
            
            # 合并所有认证信息
            return {
                **storage_state,
                **enhanced_auth,
                'timestamp': time.time()
            }
            
        except Exception as e:
            self.logger.error(f"获取主浏览器认证状态失败: {e}")
            return None
    
    def _has_auth_state_changed(self, current_state: Dict[str, Any]) -> bool:
        """智能检测认证状态是否发生了重要变化"""
        if not self.auth_state:
            return True  # 第一次获取
        
        try:
            # 检查 Cookies 数量和内容变化
            old_cookies = self.auth_state.get('cookies', [])
            new_cookies = current_state.get('cookies', [])
            
            if len(old_cookies) != len(new_cookies):
                self.logger.debug(f"Cookies数量变化: {len(old_cookies)} -> {len(new_cookies)}")
                return True
            
            # 检查重要Cookie值的变化
            important_cookie_names = ['session', 'token', 'auth', 'jwt', 'csrf', 'xsrf']
            old_cookie_dict = {c.get('name'): c.get('value') for c in old_cookies}
            new_cookie_dict = {c.get('name'): c.get('value') for c in new_cookies}
            
            for cookie_name in old_cookie_dict:
                lower_name = cookie_name.lower()
                if any(important in lower_name for important in important_cookie_names):
                    if old_cookie_dict[cookie_name] != new_cookie_dict.get(cookie_name):
                        self.logger.debug(f"重要Cookie '{cookie_name}' 发生变化")
                        return True
            
            # 检查 JWT Token 变化
            old_jwt = self.auth_state.get('jwt_tokens', {})
            new_jwt = current_state.get('jwt_tokens', {})
            
            if old_jwt != new_jwt:
                self.logger.debug("JWT Token状态发生变化")
                return True
            
            # 检查 localStorage/sessionStorage 中的重要项目
            for storage_type in ['localStorage', 'sessionStorage']:
                old_storage = self.auth_state.get(storage_type, {})
                new_storage = current_state.get(storage_type, {})
                
                important_keys = [k for k in old_storage.keys() 
                                if any(important in k.lower() 
                                     for important in ['token', 'auth', 'user', 'session', 'jwt'])]
                
                for key in important_keys:
                    if old_storage.get(key) != new_storage.get(key):
                        self.logger.debug(f"{storage_type} 中 '{key}' 发生变化")
                        return True
            
            return False  # 没有检测到重要变化
            
        except Exception as e:
            self.logger.error(f"检测认证状态变化时出错: {e}")
            return False  # 出错时保守的不同步
    
    async def _sync_auth_state_to_standalone(self, new_auth_state: Dict[str, Any]):
        """将新的认证状态同步到独立浏览器的所有context"""
        try:
            # 获取所有可用的context
            contexts_to_sync = []
            temp_contexts = []
            
            # 从池中取出所有context
            while not self.pool.empty():
                try:
                    ctx = await asyncio.wait_for(self.pool.get(), timeout=0.1)
                    contexts_to_sync.append(ctx)
                except asyncio.TimeoutError:
                    break
            
            sync_count = 0
            for ctx in contexts_to_sync:
                try:
                    # 更新 Cookies
                    if 'cookies' in new_auth_state:
                        await ctx.clear_cookies()
                        await ctx.add_cookies(new_auth_state['cookies'])
                    
                    # 更新 localStorage 和 sessionStorage
                    # 需要先创建一个页面来执行脚本
                    pages = ctx.pages
                    if not pages:
                        page = await ctx.new_page()
                        pages = [page]
                    
                    for page in pages[:1]:  # 只在第一个页面上操作
                        if not page.is_closed():
                            # 更新 localStorage
                            if 'localStorage' in new_auth_state:
                                await page.evaluate("""
                                    (storage_data) => {
                                        try {
                                            localStorage.clear();
                                            for (const [key, value] of Object.entries(storage_data)) {
                                                localStorage.setItem(key, value);
                                            }
                                        } catch (e) {
                                            console.warn('Failed to update localStorage:', e);
                                        }
                                    }
                                """, new_auth_state['localStorage'])
                            
                            # 更新 sessionStorage  
                            if 'sessionStorage' in new_auth_state:
                                await page.evaluate("""
                                    (storage_data) => {
                                        try {
                                            sessionStorage.clear();
                                            for (const [key, value] of Object.entries(storage_data)) {
                                                sessionStorage.setItem(key, value);
                                            }
                                        } catch (e) {
                                            console.warn('Failed to update sessionStorage:', e);
                                        }
                                    }
                                """, new_auth_state['sessionStorage'])
                    
                    sync_count += 1
                    
                except Exception as e:
                    self.logger.warning(f"同步单个context时出错: {e}")
                    
                # 将context放回池中
                await self.pool.put(ctx)
            
            self.logger.info(f"成功同步认证状态到 {sync_count} 个context")
            
        except Exception as e:
            self.logger.error(f"同步认证状态到独立浏览器失败: {e}", exc_info=True)
    
    async def _setup_auth_change_listeners(self):
        """
        为主浏览器设置基于事件的实时认证状态变化监听器
        这样可以更接近shared模式的实时特性
        """
        try:
            if not self.main_browser.contexts:
                return
            
            main_context = self.main_browser.contexts[0]
            if not main_context.pages:
                return
            
            main_page = main_context.pages[0]
            
            # 监听页面的存储事件（localStorage/sessionStorage变化）
            await main_page.add_init_script("""
                () => {
                    const originalSetItem = localStorage.setItem;
                    const originalRemoveItem = localStorage.removeItem;
                    const originalClear = localStorage.clear;
                    const originalSessionSetItem = sessionStorage.setItem;
                    const originalSessionRemoveItem = sessionStorage.removeItem;
                    const originalSessionClear = sessionStorage.clear;
                    
                    // 重写 localStorage 方法来触发自定义事件
                    localStorage.setItem = function(key, value) {
                        originalSetItem.call(this, key, value);
                        window.dispatchEvent(new CustomEvent('authStateChanged', {
                            detail: { type: 'localStorage', action: 'set', key, value }
                        }));
                    };
                    
                    localStorage.removeItem = function(key) {
                        originalRemoveItem.call(this, key);
                        window.dispatchEvent(new CustomEvent('authStateChanged', {
                            detail: { type: 'localStorage', action: 'remove', key }
                        }));
                    };
                    
                    localStorage.clear = function() {
                        originalClear.call(this);
                        window.dispatchEvent(new CustomEvent('authStateChanged', {
                            detail: { type: 'localStorage', action: 'clear' }
                        }));
                    };
                    
                    // 重写 sessionStorage 方法
                    sessionStorage.setItem = function(key, value) {
                        originalSessionSetItem.call(this, key, value);
                        window.dispatchEvent(new CustomEvent('authStateChanged', {
                            detail: { type: 'sessionStorage', action: 'set', key, value }
                        }));
                    };
                    
                    sessionStorage.removeItem = function(key) {
                        originalSessionRemoveItem.call(this, key);
                        window.dispatchEvent(new CustomEvent('authStateChanged', {
                            detail: { type: 'sessionStorage', action: 'remove', key }
                        }));
                    };
                    
                    sessionStorage.clear = function() {
                        originalSessionClear.call(this);
                        window.dispatchEvent(new CustomEvent('authStateChanged', {
                            detail: { type: 'sessionStorage', action: 'clear' }
                        }));
                    };
                    
                    // 监听认证相关的关键词变化
                    const authKeywords = ['token', 'jwt', 'auth', 'session', 'user', 'csrf'];
                    
                    window.addEventListener('authStateChanged', (event) => {
                        const { type, action, key, value } = event.detail;
                        
                        // 检查是否是认证相关的变化
                        if (key && authKeywords.some(keyword => 
                            key.toLowerCase().includes(keyword))) {
                            
                            // 设置一个标记，告诉Playwright这是一个重要的认证变化
                            window._authChangeDetected = true;
                            window._authChangeTime = Date.now();
                            window._authChangeDetail = { type, action, key };
                            
                            console.log(`🔐 认证状态变化检测: ${type}.${key} -> ${action}`);
                        }
                    });
                }
            """)
            
            # 启动实时监听任务
            asyncio.create_task(self._realtime_auth_listener(main_page))
            self.logger.info("✅ 实时认证变化监听器设置完成")
            
        except Exception as e:
            self.logger.error(f"设置认证变化监听器失败: {e}")
    
    async def _realtime_auth_listener(self, page: Page):
        """
        实时监听主页面的认证状态变化
        这是更接近shared模式实时性的方案
        """
        self.logger.info("🎧 启动实时认证状态监听...")
        
        while True:
            try:
                await asyncio.sleep(self.realtime_check_interval)  # 使用配置的实时检查间隔
                
                if page.is_closed() or not self.main_browser.is_connected():
                    break
                
                # 检查页面是否检测到认证变化
                auth_change_detected = await page.evaluate("""
                    () => {
                        if (window._authChangeDetected) {
                            const result = {
                                detected: true,
                                time: window._authChangeTime,
                                detail: window._authChangeDetail
                            };
                            // 重置标记
                            window._authChangeDetected = false;
                            return result;
                        }
                        return { detected: false };
                    }
                """)
                
                if auth_change_detected.get('detected', False):
                    detail = auth_change_detected.get('detail', {})
                    self.logger.info(
                        f"⚡ 实时检测到认证变化: {detail.get('type')}.{detail.get('key')} -> {detail.get('action')}"
                    )
                    
                    # 立即触发同步（而不是等待定时检查）
                    current_auth_state = await self._get_current_main_browser_auth_state()
                    if current_auth_state and self._has_auth_state_changed(current_auth_state):
                        self.logger.info("🚀 触发实时认证同步...")
                        await self._sync_auth_state_to_standalone(current_auth_state)
                        self.auth_state = current_auth_state
                        self.last_auth_sync = time.time()
                        self.logger.info("✅ 实时认证同步完成")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"实时认证监听出错: {e}")
                await asyncio.sleep(5)  # 出错时稍微延长间隔
        
        self.logger.info("🔇 实时认证状态监听已停止")
    
    async def close(self):
        """关闭池中所有的上下文和浏览器实例。"""
        self.logger.info("正在关闭浏览器池...")
        
        # 取消所有后台任务
        tasks_to_cancel = []
        
        # 取消清理任务
        if self.cleanup_task and not self.cleanup_task.done():
            tasks_to_cancel.append(self.cleanup_task)
            self.cleanup_task.cancel()
        
        # 取消认证同步任务
        if self.auth_sync_task and not self.auth_sync_task.done():
            tasks_to_cancel.append(self.auth_sync_task)
            self.auth_sync_task.cancel()
        
        # 等待所有取消的任务完成
        for task in tasks_to_cancel:
            try:
                await task
            except asyncio.CancelledError:
                pass
        
        # 关闭所有context
        closed_count = 0
        while not self.pool.empty():
            try:
                context = await asyncio.wait_for(self.pool.get(), timeout=1.0)
                await self._close_context(context)
                closed_count += 1
            except asyncio.TimeoutError:
                self.logger.warning("获取上下文超时，跳过")
                break
        
        self.logger.info(f"已关闭 {closed_count} 个池中的context")
        
        # 清理活跃的contexts
        if self.active_contexts:
            self.logger.warning(f"仍有 {len(self.active_contexts)} 个活跃的context未归还")
        
        # 安全关闭浏览器
        if self.mode == 'standalone' and self.browser and self.browser.is_connected():
            try:
                await asyncio.wait_for(self.browser.close(), timeout=5.0)
                self.logger.info("浏览器已关闭")
            except asyncio.TimeoutError:
                self.logger.warning("浏览器关闭超时")
            except Exception as e:
                self.logger.error(f"关闭浏览器时出错: {e}")
        
        self.logger.info("浏览器池已安全关闭。")


class ContextWrapper:
    """
    包装器类，让共享模式的页面看起来像一个context
    """
    def __init__(self, page: Page, context: BrowserContext):
        self.pages = [page]
        self.context = context
        self._page = page  # 主页面
    
    async def new_page(self) -> Page:
        """创建新页面"""
        # 在共享模式下，直接返回已有的页面
        return self._page
    
    async def close(self):
        """关闭所有页面"""
        for page in self.pages:
            if not page.is_closed():
                await page.close()
    
    async def clear_cookies(self):
        """清除cookies"""
        await self.context.clear_cookies()
    
    async def clear_permissions(self):
        """清除权限"""
        await self.context.clear_permissions()
    
    async def storage_state(self):
        """获取存储状态"""
        return await self.context.storage_state()
    
    async def add_init_script(self, script: str):
        """添加初始化脚本"""
        await self.context.add_init_script(script)
    
    def __getattr__(self, name):
        """代理到实际的context"""
        return getattr(self.context, name)

