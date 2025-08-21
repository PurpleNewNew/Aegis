import asyncio
import logging
from asyncio import Queue
from urllib.parse import urlparse, urlunparse
from playwright.async_api import Page, Frame, Browser
from typing import Dict, Any, Optional
from src.tools import auth_tools

class CDPController:
    """
    作为"侦察兵"，使用一个已连接的浏览器实例，监控页面导航和交互事件，
    并将目标URL和完整的认证状态发送给InvestigationManager。
    """

    def __init__(self, output_q: Queue, config: dict):
        self.output_q = output_q
        self.config = config
        self.whitelist_domains = config.get('scanner_scope', {}).get('whitelist_domains', [])
        self.logger = logging.getLogger(self.__class__.__name__)
        self.reported_endpoints = set() # 修改：从记录完整URL改为记录规范化后的端点

    def _normalize_url(self, url: str) -> str:
        """将URL规范化，去除查询参数和片段，得到基础端点。"""
        try:
            parsed = urlparse(url)
            # 只保留 scheme, netloc, path
            return urlunparse((parsed.scheme, parsed.netloc, parsed.path, '', '', ''))
        except Exception:
            return url # 解析失败则返回原URL

    def _is_in_whitelist(self, url: str) -> bool:
        if not url or not url.startswith(('http://', 'https://')):
            return False
        if not self.whitelist_domains:
            self.logger.warning("白名单为空，将拒绝所有请求以保证安全。")
            return False
        try:
            hostname = urlparse(url).hostname
            if not hostname:
                return False
            for domain in self.whitelist_domains:
                if hostname == domain or hostname.endswith(f'.{domain}'):
                    return True
            return False
        except Exception:
            return False

    async def handle_frame_navigated(self, frame: Frame):
        try:
            if not frame.page or frame.page.is_closed() or not frame.page.context or not frame.page.context.browser or not frame.page.context.browser.is_connected():
                return
            if frame.parent_frame:
                return
        except Exception:
            return
            
        full_url = frame.url
        if not self._is_in_whitelist(full_url):
            return

        endpoint = self._normalize_url(full_url)
        is_new_endpoint = endpoint not in self.reported_endpoints

        try:
            self.logger.info(f"侦察到导航: {full_url} (端点: {endpoint}, 是否全新: {is_new_endpoint})")
            if is_new_endpoint:
                self.reported_endpoints.add(endpoint)
            
            auth_state = await auth_tools.extract_full_auth_state(frame.page)
            
            event_data = {
                'event_type': 'navigation',
                'url': full_url,
                'endpoint': endpoint,
                'is_new_endpoint': is_new_endpoint,
                'auth_state': auth_state
            }
            await self.output_q.put(event_data)

        except Exception as e:
            self.logger.warning(f"处理导航事件时出错（可能是浏览器已关闭）: {e}")

    async def setup_page_listeners(self, page: Page):
        if not self._is_in_whitelist(page.url):
            self.logger.debug(f"页面 {page.url} 不在白名单内，跳过监听器设置。")
            return

        try:
            self.logger.info(f"为白名单页面设置导航和交互监听器: {page.url}")
            page.on("framenavigated", self.handle_frame_navigated)

            async def on_user_interaction(interaction_data: Dict[str, Any]):
                if not isinstance(interaction_data, dict) or not interaction_data.get('selector'):
                    self.logger.debug(f"收到格式不完整或无选择器的交互事件，已忽略: {interaction_data}")
                    return
                
                if not page.is_closed() and self._is_in_whitelist(page.url):
                    try:
                        auth_state = await auth_tools.extract_full_auth_state(page)
                        event_data = {
                            'event_type': 'user_interaction',
                            'url': page.url,
                            'interaction_type': interaction_data.get('type'),
                            'element_info': {
                                'selector': interaction_data.get('selector'),
                                'tag': interaction_data.get('tag'),
                                'text': interaction_data.get('text', '')[:50],
                            },
                            'auth_state': auth_state,
                            'timestamp': asyncio.get_event_loop().time()
                        }
                        self.logger.info(f"侦察到用户交互: {event_data.get('interaction_type')} on {event_data.get('element_info', {}).get('selector')}")
                        await self.output_q.put(event_data)
                    except Exception as e:
                        self.logger.warning(f"处理用户交互事件时出错（页面可能已关闭）。错误: {repr(e)}，收到的数据: {interaction_data}", exc_info=True)

            await page.expose_function("onUserInteraction", on_user_interaction)

            await page.add_init_script(r"""(function() {
                function getCssSelector(el) {
                    if (!(el instanceof Element)) return;
                    let path = [];
                    while (el.nodeType === Node.ELEMENT_NODE) {
                        let selector = el.nodeName.toLowerCase();
                        if (el.id) {
                            selector += '#' + el.id;
                            path.unshift(selector);
                            break;
                        } else {
                            let sib = el, nth = 1;
                            while (sib = sib.previousElementSibling) {
                                if (sib.nodeName.toLowerCase() == selector)
                                    nth++;
                            }
                            if (nth != 1)
                                selector += ":nth-of-type("+nth+")";
                        }
                        path.unshift(selector);
                        el = el.parentNode;
                    }
                    return path.join(" > ");
                }

                document.addEventListener('click', (e) => {
                    if (e.target) {
                         window.onUserInteraction({
                            type: 'click',
                            selector: getCssSelector(e.target),
                            tag: e.target.tagName,
                            text: e.target.innerText || e.target.value
                        });
                    }
                }, true);

                document.addEventListener('submit', (e) => {
                    if (e.target) {
                         window.onUserInteraction({
                            type: 'submit',
                            selector: getCssSelector(e.target),
                            tag: e.target.tagName
                        });
                    }
                }, true);
            })();""")
        except Exception as e:
            self.logger.error(f"为页面 {page.url} 设置监听器失败: {e}")

    async def run(self, browser: Browser):
        self.logger.info("侦察兵控制器(CDPController)正在启动并接管浏览器...")
        try:
            if not browser.is_connected():
                self.logger.error("传入的浏览器实例未连接！")
                return

            if not browser.contexts:
                logging.warning("浏览器没有活动的上下文。")
                return

            context = browser.contexts[0]
            
            for page in context.pages:
                await self.setup_page_listeners(page)
            
            context.on("page", self.setup_page_listeners)

            self.logger.info("侦察兵已在所有现有和未来页面上设置监听器。")
            await asyncio.Event().wait()

        except asyncio.CancelledError:
            self.logger.info("侦察兵控制器任务被取消。")
        except Exception as e:
            self.logger.error(f"侦察兵控制器发生意外错误: {e}", exc_info=True)
        finally:
            self.logger.info("侦察兵控制器已关闭。")