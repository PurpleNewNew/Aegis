import asyncio
import logging
import yaml
import os
import time
from playwright.async_api import async_playwright, Browser, Playwright
from urllib.parse import urlparse

# 禁用ChromaDB遥测功能以防止网络连接警告
os.environ['ANONYMIZED_TELEMETRY'] = 'False'

# 配置基础日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# 导入队列
from src.queues.queues import (
    navigation_q,
    debug_events_q,
    ai_output_q,
    reporter_q,
    memory_q
)

# 导入组件
from src.controller.cdp_controller import CDPController
from src.controller.cdp_debugger import CDPDebugger
from src.workers.investigation_manager import InvestigationManager
from src.workers.broadcaster import Broadcaster
from src.workers.reporter_worker import ReporterWorker
from src.workers.memory_worker import MemoryWorker
from src.tools import auth_tools

async def wait_for_browser(playwright: Playwright, config: dict) -> Browser:
    """
    等待并重复尝试连接到远程调试端口，直到成功。
    """
    port = config['browser']['remote_debugging_port']
    retry_interval = config.get('browser', {}).get('connection_retry_interval', 5)
    
    while True:
        try:
            logging.info(f"正在尝试连接到端口 {port} 上的Chrome浏览器...")
            browser = await playwright.chromium.connect_over_cdp(f"http://localhost:{port}")
            logging.info("✅ 成功连接到Chrome浏览器！")
            browser.on("disconnected", lambda: logging.error("与主浏览器的连接已断开！请重启Aegis和浏览器。"))
            return browser
        except Exception as e:
            if "ECONNREFUSED" in str(e):
                logging.info(f"连接被拒绝。正在等待浏览器在端口 {port} 上启动... 将在 {retry_interval} 秒后重试。")
            else:
                logging.warning(f"连接浏览器时发生未知错误: {e}")
            await asyncio.sleep(retry_interval)

def is_in_whitelist(url: str, config: dict) -> bool:
    """检查URL是否在白名单内。"""
    whitelist_domains = config.get('scanner_scope', {}).get('whitelist_domains', [])
    if not url or not url.startswith(('http://', 'https://')):
        return False
    if not whitelist_domains:
        return False
    try:
        hostname = urlparse(url).hostname
        if not hostname:
            return False
        return any(hostname == domain or hostname.endswith(f'.{domain}') for domain in whitelist_domains)
    except Exception:
        return False

async def main():
    """
    初始化并运行Aegis应用的所有组件，采用集中式Playwright和浏览器连接管理。
    """
    logging.info("Aegis应用正在启动 (vFinal - 增强启动逻辑)...")

    try:
        with open('config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        logging.info("配置加载成功。")
    except Exception as e:
        logging.error(f"加载或解析配置文件失败: {e}")
        return

    os.makedirs(config.get('reporter', {}).get('output_dir', './reports'), exist_ok=True)
    os.makedirs(os.path.dirname(config.get('logging', {}).get('ai_dialogues_file', './logs/ai_dialogues.jsonl')), exist_ok=True)

    running_tasks = []
    manager = None
    playwright = None
    browser = None
    try:
        playwright = await async_playwright().start()
        browser = await wait_for_browser(playwright, config)

        # --- 增强的启动逻辑 --- #
        logging.info("正在扫描已打开的标签页以获取初始认证和目标...")
        initial_auth_state = None
        initial_targets = []
        if browser.contexts:
            context = browser.contexts[0]
            for page in context.pages:
                if is_in_whitelist(page.url, config):
                    logging.info(f"发现白名单内的已打开页面: {page.url}")
                    if not initial_auth_state:
                        logging.info(f"将页面 {page.url} 作为认证状态来源。")
                        initial_auth_state = await auth_tools.extract_full_auth_state(page)
                    initial_targets.append({'event_type': 'navigation', 'url': page.url, 'auth_state': initial_auth_state})
        
        if initial_targets:
            logging.info(f"已从打开的标签页中识别出 {len(initial_targets)} 个初始调查目标。")
            for target in initial_targets:
                await navigation_q.put(target)
        else:
            logging.info("未发现已打开的白名单页面。将等待新的导航事件。")
        # --- 启动逻辑结束 --- #

        logging.info("正在初始化所有核心服务...")
        scout = CDPController(output_q=navigation_q, config=config)
        debugger = CDPDebugger(output_q=debug_events_q, config=config)
        manager = InvestigationManager(input_q=navigation_q, output_q=ai_output_q, debug_q=debug_events_q, config=config)
        await manager.initialize(browser, playwright, initial_auth_state)
        broadcaster = Broadcaster(input_q=ai_output_q, output_queues=[reporter_q, memory_q])
        reporter = ReporterWorker(input_q=reporter_q, config=config)
        memory = MemoryWorker(input_q=memory_q, config=config)

        running_tasks.extend([
            asyncio.create_task(scout.run(browser), name="CDPScout"),
            asyncio.create_task(debugger.run(browser), name="CDPDebugger"),
            asyncio.create_task(manager.run(), name="InvestigationManager"),
            asyncio.create_task(broadcaster.run(), name="Broadcaster"),
            asyncio.create_task(reporter.run(), name="ReporterWorker"),
            asyncio.create_task(memory.run(), name="MemoryWorker")
        ])

        logging.info(f"Aegis所有 {len(running_tasks)} 个模块已启动。")
        await asyncio.gather(*running_tasks)

    except asyncio.CancelledError:
        logging.info("应用主任务收到关闭信号...")
    finally:
        logging.info("正在优雅地关闭所有服务...")
        for task in running_tasks:
            task.cancel()
        await asyncio.gather(*running_tasks, return_exceptions=True)
        if manager:
            await manager.close()
        if browser and browser.is_connected():
            await browser.close()
        if playwright:
            await playwright.stop()
        logging.info("Aegis已完全关闭。")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("用户请求关闭。")
