import asyncio
import logging
import yaml
import os
from playwright.async_api import async_playwright, Browser

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
    memory_q,
    controller_status_q
)

# 创建JS逆向专用队列
from asyncio import Queue
js_hook_events_q = Queue()
network_data_q = Queue()

# 导入组件
from src.controller.cdp_controller import CDPController
from src.controller.unified_cdp_debugger import UnifiedCDPDebugger
from src.workers.investigation_manager import InvestigationManager
from src.workers.broadcaster import Broadcaster
from src.workers.reporter_worker import ReporterWorker
from src.workers.memory_worker import MemoryWorker
from src.workers.js_reverse_worker import JSReverseWorker

async def main():
    """
    初始化并运行Aegis应用的所有组件，采用集中式Playwright生命周期管理。
    """
    logging.info("Aegis应用正在启动 (vFinal - 集中式Playwright管理)...")

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
        # 步骤 1: 集中启动Playwright
        # --------------------------------------------------------------------
        playwright = await async_playwright().start()
        logging.info("Playwright引擎已启动。")

        # --------------------------------------------------------------------
        # 步骤 2: 连接到主浏览器
        # --------------------------------------------------------------------
        browser_config = config.get('browser', {})
        browser = await playwright.chromium.connect_over_cdp(f"http://localhost:{browser_config['remote_debugging_port']}")
        logging.info("成功连接到主浏览器实例。")

        # --------------------------------------------------------------------
        # 步骤 3: 协同初始化，传入共享的实例
        # --------------------------------------------------------------------
        manager = InvestigationManager(input_q=navigation_q, output_q=ai_output_q, debug_q=debug_events_q, config=config)
        await manager.initialize(browser, playwright)
        logging.info("调查管理器和浏览器池初始化成功。")

        scout = CDPController(output_q=navigation_q, config=config)
        debugger = UnifiedCDPDebugger(
            output_q=debug_events_q, 
            config=config, 
            network_data_q=network_data_q, 
            js_hook_events_q=js_hook_events_q
        )
        broadcaster = Broadcaster(input_q=ai_output_q, output_queues=[reporter_q, memory_q])
        reporter = ReporterWorker(input_q=reporter_q, config=config)
        memory = MemoryWorker(input_q=memory_q, config=config)
        
        # 初始化JS逆向工作器（如果启用）
        js_reverse_worker = None
        if config.get('js_reverse', {}).get('enabled', False):
            js_reverse_worker = JSReverseWorker(
                config=config,
                debug_q=debug_events_q,
                js_hook_events_q=js_hook_events_q,
                network_data_q=network_data_q
            )
            running_tasks.append(
                asyncio.create_task(js_reverse_worker.run(), name="JSReverseWorker")
            )
            logging.info("JS逆向功能已启用。")

        running_tasks.extend([
            asyncio.create_task(scout.run(browser), name="CDPScout"),
            asyncio.create_task(debugger.run(browser), name="UnifiedCDPDebugger"),
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
            if not task.done():
                task.cancel()
        
        results = await asyncio.gather(*running_tasks, return_exceptions=True)
        for i, result in enumerate(results):
            task_name = running_tasks[i].get_name()
            if isinstance(result, asyncio.CancelledError):
                logging.info(f"任务 '{task_name}' 已成功取消。")
            elif isinstance(result, Exception):
                logging.warning(f"任务 '{task_name}' 在关闭时出现异常: {result}")
        
        logging.info("所有后台任务已停止。")

        if manager:
            try:
                await asyncio.wait_for(manager.close(), timeout=15.0)
                logging.info("调查管理器已安全关闭。")
            except asyncio.TimeoutError:
                logging.warning("调查管理器关闭超时。")
            except Exception as e:
                logging.error(f"关闭调查管理器时发生严重错误: {e}", exc_info=True)
        
        if browser and browser.is_connected():
            await browser.close()
            logging.info("主浏览器连接已关闭。")

        if playwright:
            await playwright.stop()
            logging.info("Playwright引擎已关闭。")

        logging.info("Aegis已完全关闭。")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("用户请求关闭。")