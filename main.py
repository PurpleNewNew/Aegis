import asyncio
import logging
import yaml
import os
import time
from playwright.async_api import async_playwright, Browser, Playwright

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
            # 监听断开连接事件
            browser.on("disconnected", lambda: logging.error("与主浏览器的连接已断开！请重启Aegis和浏览器。"))
            return browser
        except Exception as e:
            # 简化错误信息，避免刷屏
            if "ECONNREFUSED" in str(e):
                logging.info(f"连接被拒绝。正在等待浏览器在端口 {port} 上启动... 将在 {retry_interval} 秒后重试。")
            else:
                logging.warning(f"连接浏览器时发生未知错误: {e}")
            
            await asyncio.sleep(retry_interval)

async def main():
    """
    初始化并运行Aegis应用的所有组件，采用集中式Playwright和浏览器连接管理。
    """
    logging.info("Aegis应用正在启动 (vFinal - 集中式连接管理)...")

    # 1. 加载配置
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
        # --------------------------------------------------------------------
        # 步骤 1: 启动Playwright并等待浏览器连接
        # --------------------------------------------------------------------
        playwright = await async_playwright().start()
        browser = await wait_for_browser(playwright, config)

        # --------------------------------------------------------------------
        # 步骤 2: 初始化所有核心组件，并传入已连接的浏览器实例
        # --------------------------------------------------------------------
        logging.info("浏览器已连接。正在初始化所有服务...")
        
        # 控制器现在直接接收browser对象
        scout = CDPController(output_q=navigation_q, config=config)
        debugger = CDPDebugger(output_q=debug_events_q, config=config)
        
        # 管理器也接收browser对象以初始化浏览器池
        manager = InvestigationManager(input_q=navigation_q, output_q=ai_output_q, debug_q=debug_events_q, config=config)
        await manager.initialize(browser, playwright)
        
        broadcaster = Broadcaster(input_q=ai_output_q, output_queues=[reporter_q, memory_q])
        reporter = ReporterWorker(input_q=reporter_q, config=config)
        memory = MemoryWorker(input_q=memory_q, config=config)

        # --------------------------------------------------------------------
        # 步骤 3: 启动所有任务
        # --------------------------------------------------------------------
        running_tasks.extend([
            asyncio.create_task(scout.run(browser), name="CDPScout"),
            asyncio.create_task(debugger.run(browser), name="CDPDebugger"),
            asyncio.create_task(manager.run(), name="InvestigationManager"),
            asyncio.create_task(broadcaster.run(), name="Broadcaster"),
            asyncio.create_task(reporter.run(), name="ReporterWorker"),
            asyncio.create_task(memory.run(), name="MemoryWorker")
        ])

        # --------------------------------------------------------------------
        # 步骤 4: 运行
        # --------------------------------------------------------------------
        logging.info(f"Aegis所有 {len(running_tasks)} 个模块已启动。请开始浏览网页...")
        await asyncio.gather(*running_tasks)

    except asyncio.CancelledError:
        logging.info("应用主任务收到关闭信号...")
    finally:
        logging.info("正在优雅地关闭所有服务...")

        for task in running_tasks:
            task.cancel()
        
        results = await asyncio.gather(*running_tasks, return_exceptions=True)
        # (此处可以添加对关闭结果的日志记录)
        
        if manager:
            await manager.close()
        
        # 在所有任务和服务都关闭后，断开与浏览器的连接
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