
import asyncio
import logging
from asyncio import Queue
from playwright.async_api import async_playwright, Page

class CDPController:
    """
    使用 Playwright 通过远程调试端口连接到一个正在运行的Chrome实例，
    并将网络事件流式传输到队列中以供进一步处理。
    """

    def __init__(self, output_q: Queue, config: dict):
        """
        初始化控制器。

        Args:
            output_q: 用于发送原始CDP事件的队列。
            config: 应用程序的配置字典。
        """
        self.output_q = output_q
        self.port = config['browser']['remote_debugging_port']
        self.logger = logging.getLogger(self.__class__.__name__)

    async def handle_request(self, request):
        """
        处理'request'事件的事件处理器。
        将一个结构化的事件放入输出队列。
        """
        try:
            event = {
                'event_type': 'request',
                'method': request.method,
                'url': request.url,
                'headers': await request.all_headers(),
                'post_data': request.post_data_buffer.hex() if request.post_data_buffer else None,
                'resource_type': request.resource_type
            }
            await self.output_q.put(event)
            self.logger.info(f"已捕获请求: {event['method']} {event['url']}")
        except Exception as e:
            self.logger.error(f"处理请求事件时出错 {request.url}: {e}")

    async def setup_page_listeners(self, page: Page):
        """为给定的页面附加所有必要的事件监听器。"""
        try:
            self.logger.info(f"为页面设置监听器: {await page.title()}")
            page.on("request", self.handle_request)
            # 你可以在这里添加更多的监听器，例如：用于响应、控制台日志等。
            # page.on("response", self.handle_response)
        except Exception as e:
            self.logger.error(f"为页面设置监听器失败。页面可能已关闭。错误: {e}")

    async def run(self):
        """
        连接到浏览器，为现有和新页面附加监听器，
        并保持运行以监控所有活动。
        """
        self.logger.info(f"尝试连接到端口 {self.port} 上的Chrome浏览器...")
        async with async_playwright() as p:
            try:
                browser = await p.chromium.connect_over_cdp(f"http://localhost:{self.port}")
                self.logger.info("成功连接到Chrome。")
                
                context = browser.contexts[0]

                # 1. 为所有当前打开的页面设置监听器
                for page in context.pages:
                    await self.setup_page_listeners(page)

                # 2. 为任何新创建的页面设置监听器
                context.on("page", self.setup_page_listeners)

                self.logger.info("CDP控制器现在正在监控所有当前和未来的页面。")
                
                # 保持任务存活以监听事件
                while browser.is_connected():
                    await asyncio.sleep(1)

            except (ConnectionRefusedError, asyncio.TimeoutError):
                self.logger.error(
                    f"连接到端口 {self.port} 上的Chrome失败。"
                    f"请确保Chrome正在以 '--remote-debugging-port={self.port}' 参数运行。"
                )
            except Exception as e:
                self.logger.error(f"CDP控制器发生意外错误: {e}", exc_info=True)
            finally:
                self.logger.info("CDP控制器已关闭。")
                if 'browser' in locals() and browser.is_connected():
                    await browser.close()
