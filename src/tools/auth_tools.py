import logging
import asyncio
from urllib.parse import urlparse
from playwright.async_api import Page
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

async def extract_full_auth_state(page: Page) -> Optional[Dict[str, Any]]:
    """
    从给定页面提取完整的认证状态，包括Cookies, LocalStorage和SessionStorage。
    """
    try:
        cookies = await page.context.cookies()
        storage = await page.evaluate("""() => {
            const ls = {}, ss = {};
            try {
                for (let i=0; i<localStorage.length; i++) { ls[localStorage.key(i)] = localStorage.getItem(localStorage.key(i)); }
                for (let i=0; i<sessionStorage.length; i++) { ss[sessionStorage.key(i)] = sessionStorage.getItem(sessionStorage.key(i)); }
            } catch (e) {}
            return { localStorage: ls, sessionStorage: ss };
        }""")
        return {"cookies": cookies, **storage}
    except Exception as e:
        logger.error(f"提取完整认证状态时出错: {e}")
        return None

async def inject_auth_state(page: Page, auth_state: Dict[str, Any], max_retries: int = 3) -> bool:
    """
    将一个完整的认证状态（Cookies, LocalStorage, SessionStorage）注入到当前页面。
    这是实现"身份复制"的核心。
    增加了域名验证和重试逻辑。
    """
    for attempt in range(max_retries):
        try:
            # Wait for page to be ready
            if page.url in ['about:blank', 'about:page', 'chrome://newtab/', ''] or not page.url.startswith('http'):
                if attempt < max_retries - 1:
                    await asyncio.sleep(1)
                    continue
                else:
                    logger.debug(f"跳过在特殊页面 '{page.url}' 上注入认证状态")
                    return False
            
            # 1. 注入Cookies with domain validation
            cookies = auth_state.get('cookies', [])
            if cookies:
                current_domain = urlparse(page.url).netloc
                valid_cookies = []
                
                for cookie in cookies:
                    cookie_domain = cookie.get('domain', '')
                    if not cookie_domain or cookie_domain in [current_domain, f'.{current_domain}']:
                        valid_cookies.append(cookie)
                    elif cookie_domain.startswith('.'):
                        # Handle wildcard domains
                        base_domain = cookie_domain[1:]
                        if current_domain.endswith(base_domain):
                            valid_cookies.append(cookie)
                
                if valid_cookies:
                    await page.context.add_cookies(valid_cookies)
                    logger.info(f"成功向页面注入 {len(valid_cookies)} 个有效Cookie（过滤了 {len(cookies) - len(valid_cookies)} 个无效Cookie）")
                else:
                    logger.warning("没有找到适用于当前域名的Cookie")

            # 2. 注入LocalStorage和SessionStorage with retry logic
            local_storage = auth_state.get('localStorage', {}) or auth_state.get('local_storage', {}) or auth_state.get('localstorage', {})
            session_storage = auth_state.get('sessionStorage', {}) or auth_state.get('session_storage', {}) or auth_state.get('sessionstorage', {})
            
            if local_storage or session_storage:
                try:
                    # Wait for page to fully load
                    await page.wait_for_load_state('domcontentloaded', timeout=5000)
                    
                    inject_result = await page.evaluate("""(storages) => {
                        const results = { local: 0, session: 0, errors: [] };
                        
                        const populate = (storage, data, type) => {
                            for (const [key, value] of Object.entries(data)) {
                                try {
                                    storage.setItem(key, value);
                                    if (type === 'local') results.local++;
                                    else results.session++;
                                } catch (e) {
                                    results.errors.push(`${type}Storage ${key}: ${e.message}`);
                                }
                            }
                        };
                        
                        try {
                            if (storages.local && Object.keys(storages.local).length > 0) {
                                populate(window.localStorage, storages.local, 'local');
                            }
                        } catch (e) {
                            results.errors.push(`localStorage access: ${e.message}`);
                        }
                        
                        try {
                            if (storages.session && Object.keys(storages.session).length > 0) {
                                populate(window.sessionStorage, storages.session, 'session');
                            }
                        } catch (e) {
                            results.errors.push(`sessionStorage access: ${e.message}`);
                        }
                        
                        return results;
                    }""", {"local": local_storage, "session": session_storage})
                    
                    logger.info(f"成功注入LocalStorage ({inject_result.get('local', 0)}项) 和 SessionStorage ({inject_result.get('session', 0)}项)")
                    
                    if inject_result.get('errors'):
                        for error in inject_result['errors'][:3]:  # Log first 3 errors
                            logger.warning(f"存储注入警告: {error}")
                            
                except Exception as e:
                    if attempt < max_retries - 1:
                        logger.warning(f"存储注入失败（尝试 {attempt + 1}/{max_retries}）: {e}")
                        await asyncio.sleep(1)
                        continue
                    else:
                        logger.error(f"存储注入最终失败: {e}")
            
            logger.info(f"认证状态注入成功（尝试 {attempt + 1}/{max_retries}）")
            return True
            
        except Exception as e:
            if attempt < max_retries - 1:
                logger.warning(f"认证状态注入失败（尝试 {attempt + 1}/{max_retries}）: {e}")
                await asyncio.sleep(1)
            else:
                logger.error(f"认证状态注入最终失败: {e}", exc_info=True)
    
    return False

async def inject_with_retry_on_navigation(page: Page, auth_state: Dict[str, Any]) -> bool:
    """注入认证状态，并在导航后重试"""
    # Initial injection
    success = await inject_auth_state(page, auth_state)
    
    if not success:
        # Set up a listener to retry after navigation
        async def handle_navigation(response):
            if response.ok:
                await asyncio.sleep(0.5)  # Wait for page to settle
                await inject_auth_state(page, auth_state)
        
        page.on('response', handle_navigation)
    
    return success