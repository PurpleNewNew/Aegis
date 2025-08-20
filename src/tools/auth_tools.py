import logging
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

async def inject_auth_state(page: Page, auth_state: Dict[str, Any]):
    """
    将一个完整的认证状态（Cookies, LocalStorage, SessionStorage）注入到当前页面。
    这是实现“身份复制”的核心。
    """
    try:
        # 1. 注入Cookies
        cookies = auth_state.get('cookies', [])
        if cookies:
            await page.context.add_cookies(cookies)
            logger.info(f"成功向影子浏览器注入 {len(cookies)} 个Cookie。")

        # 2. 注入LocalStorage和SessionStorage
        local_storage = auth_state.get('localStorage', {}) or auth_state.get('local_storage', {}) or auth_state.get('localstorage', {})
        session_storage = auth_state.get('sessionStorage', {}) or auth_state.get('session_storage', {}) or auth_state.get('sessionstorage', {})
        
        if local_storage or session_storage:
            current_url = page.url
            if current_url in ['about:blank', 'about:page', 'chrome://newtab/', ''] or not current_url.startswith('http'):
                logger.debug(f"跳过在特殊页面 '{current_url}' 上注入localStorage/sessionStorage")
            else:
                try:
                    await page.evaluate("""(storages) => {
                        const populate = (storage, data) => {
                            for (const [key, value] of Object.entries(data)) {
                                try {
                                    storage.setItem(key, value);
                                } catch (e) {
                                    console.warn(`Failed to set storage item ${key}:`, e);
                                }
                            }
                        };
                        try {
                            if (storages.local && Object.keys(storages.local).length > 0) {
                                populate(window.localStorage, storages.local);
                            }
                        } catch (e) {
                            console.warn('Failed to access localStorage:', e);
                        }
                        try {
                            if (storages.session && Object.keys(storages.session).length > 0) {
                                populate(window.sessionStorage, storages.session);
                            }
                        } catch (e) {
                            console.warn('Failed to access sessionStorage:', e);
                        }
                    }""", {"local": local_storage, "session": session_storage})
                    logger.info(f"成功注入LocalStorage ({len(local_storage)}项) 和 SessionStorage ({len(session_storage)}项)。")
                except Exception as e:
                    logger.warning(f"在页面 '{current_url}' 上注入存储状态失败: {e}")
        
        logger.info("完整的认证状态注入成功。")
        return True
    except Exception as e:
        logger.error(f"注入认证状态时出错: {e}", exc_info=True)
        return False