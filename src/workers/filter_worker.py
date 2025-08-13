
import asyncio
import logging
from asyncio import Queue
from urllib.parse import urlparse

class FilterWorker:
    """
    从队列中提取原始事件，基于域名白名单和资源类型进行过滤，
    然后将不同类型的有价值事件分发到各自的处理队列中。
    """

    STATIC_EXTENSIONS = {
        '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico', '.bmp', '.tiff',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.css',
        '.mp4', '.webm', '.ogg', '.mp3', '.wav', '.mov',
        '.pdf',
        '.zip', '.rar', '.gz', '.tar'
    }
    BLOCKED_RESOURCE_TYPES = {'image', 'font', 'stylesheet', 'media', 'manifest'}

    def __init__(self, input_q: Queue, request_q: Queue, js_q: Queue, config: dict):
        """
        初始化Worker。

        Args:
            input_q: 用于拉取原始事件的输入队列。
            request_q: 用于推送网络请求事件的输出队列。
            js_q: 用于推送JS文件事件的输出队列。
            config: 应用程序的配置字典。
        """
        self.input_q = input_q
        self.request_q = request_q
        self.js_q = js_q
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.whitelist_domains = self.config.get('scanner_scope', {}).get('whitelist_domains', [])
        if not self.whitelist_domains:
            self.logger.warning("白名单为空！扫描器将不会分析任何域名。")
        else:
            self.logger.info(f"扫描器范围已限定为: {self.whitelist_domains}")

    def is_in_scope(self, request_url: str, initiator_url: str) -> bool:
        """检查请求或其发起者是否在白名单域名/IP范围内。"""
        if not self.whitelist_domains:
            return False
        urls_to_check = {request_url, initiator_url}
        for url in urls_to_check:
            if not url:
                continue
            try:
                hostname = urlparse(url).hostname
                if not hostname:
                    continue
                if any(hostname == whitelisted_domain or hostname.endswith('.' + whitelisted_domain) for whitelisted_domain in self.whitelist_domains):
                    return True
            except Exception:
                continue
        return False

    async def run(self):
        """
        带有增强过滤和分发功能的Worker主循环。
        """
        self.logger.info("过滤器Worker正在以增强模式运行。")
        try:
            while True:
                event = await self.input_q.get()
                event_type = event.get('event_type')
                request_url = event.get('url', '')
                initiator_url = event.get('initiator_url', '')

                if not self.is_in_scope(request_url, initiator_url):
                    self.logger.debug(f"丢弃范围之外的事件: {request_url} (发起者: {initiator_url})")
                    self.input_q.task_done()
                    continue

                if event_type == 'request':
                    resource_type = event.get('resource_type')
                    if resource_type in self.BLOCKED_RESOURCE_TYPES or any(request_url.lower().endswith(ext) for ext in self.STATIC_EXTENSIONS):
                        self.logger.info(f"按类型/扩展名丢弃静态资源: {request_url}")
                        self.input_q.task_done()
                        continue
                    
                    await self.request_q.put(event)
                    self.logger.info(f"网络请求已通过并送往关联器: {request_url}")

                elif event_type == 'javascript_file':
                    await self.js_q.put(event)
                    self.logger.info(f"JS文件已通过并送往摘要器: {request_url}")
                
                else:
                    self.logger.warning(f"未知的事件类型: {event_type}，予以丢弃。")

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("过滤器Worker正在关闭。")
        except Exception as e:
            self.logger.error(f"过滤器Worker发生错误: {e}", exc_info=True)
