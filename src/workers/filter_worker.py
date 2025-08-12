import asyncio
import logging
from asyncio import Queue
from urllib.parse import urlparse

class FilterWorker:
    """
    从队列中提取原始事件，基于域名白名单和资源类型进行过滤，
    然后将有价值的上下文推送到下一个队列。
    """

    # 更全面的静态文件扩展名列表
    STATIC_EXTENSIONS = {
        # 图片
        '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico', '.bmp', '.tiff',
        # 字体
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        # 样式表
        '.css',
        # 媒体
        '.mp4', '.webm', '.ogg', '.mp3', '.wav', '.mov',
        # 文档
        '.pdf',
        # 压缩包
        '.zip', '.rar', '.gz', '.tar'
    }

    # 通常与漏洞分析无关的资源类型
    BLOCKED_RESOURCE_TYPES = {'image', 'font', 'stylesheet', 'media', 'manifest'}

    def __init__(self, input_q: Queue, output_q: Queue, config: dict):
        """
        初始化Worker。

        Args:
            input_q: 用于拉取原始事件的输入队列。
            output_q: 用于推送精炼上下文的输出队列。
            config: 应用程序的配置字典。
        """
        self.input_q = input_q
        self.output_q = output_q
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
                # 检查主机名是否完全匹配，或是任何白名单域名的子域名
                if any(hostname == whitelisted_domain or hostname.endswith('.' + whitelisted_domain) for whitelisted_domain in self.whitelist_domains):
                    return True # 只要有一个匹配就放行
            except Exception:
                continue # 解析URL失败则跳过
        
        return False

    async def run(self):
        """
        带有增强过滤功能的Worker主循环。
        """
        self.logger.info("过滤器Worker正在以增强模式运行。")
        try:
            while True:
                event = await self.input_q.get()
                request_url = event.get('url', '')
                initiator_url = event.get('initiator_url', '')

                # 1. 上下文感知的白名单检查
                if not self.is_in_scope(request_url, initiator_url):
                    self.logger.debug(f"丢弃范围之外的请求: {request_url} (发起者: {initiator_url})")
                    self.input_q.task_done()
                    continue

                # 2. 静态资源检查 (基于资源类型)
                resource_type = event.get('resource_type')
                if resource_type in self.BLOCKED_RESOURCE_TYPES:
                    self.logger.info(f"按类型 '{resource_type}' 丢弃静态资源: {request_url}")
                    self.input_q.task_done()
                    continue

                # 3. 静态资源检查 (基于文件扩展名，作为后备方案)
                if any(request_url.lower().endswith(ext) for ext in self.STATIC_EXTENSIONS):
                    self.logger.info(f"按扩展名丢弃静态资源: {request_url}")
                    self.input_q.task_done()
                    continue

                # 如果所有检查都通过，则精炼并转发上下文
                refined_context = {
                    'type': 'network_request',
                    'url': event['url'],
                    'method': event['method'],
                    'headers': event['headers'],
                    'post_data': event['post_data'],
                    'resource_type': resource_type
                }
                await self.output_q.put(refined_context)
                self.logger.info(f"请求已通过并送去分析: {request_url}")
                
                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("过滤器Worker正在关闭。")
        except Exception as e:
            self.logger.error(f"过滤器Worker发生错误: {e}", exc_info=True)