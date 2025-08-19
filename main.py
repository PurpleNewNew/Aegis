
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

# 导入组件
from src.controller.cdp_controller import CDPController
from src.controller.cdp_debugger import CDPDebugger
from src.workers.investigation_manager import InvestigationManager
from src.workers.broadcaster import Broadcaster
from src.workers.reporter_worker import ReporterWorker
from src.workers.memory_worker import MemoryWorker

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
    try:
        # --------------------------------------------------------------------
        # 步骤 1: 集中启动Playwright
        # --------------------------------------------------------------------
        playwright = await async_playwright().start()
        logging.info("Playwright引擎已启动。")

        # --------------------------------------------------------------------
        # 步骤 2: 协同初始化，传入共享的playwright实例
        # --------------------------------------------------------------------
        logging.info("正在启动侦察兵(CDPController)...")
        scout = CDPController(output_q=navigation_q, config=config, status_q=controller_status_q, playwright=playwright)
        running_tasks.append(asyncio.create_task(scout.run(), name="CDPScout"))

        logging.info("等待侦察兵连接到主浏览器...")
        main_browser: Browser = await controller_status_q.get()

        if not main_browser or not main_browser.is_connected():
            logging.error("侦察兵未能连接到主浏览器。请检查Chrome是否已以调试模式启动。")
            return

        logging.info("侦察兵已连接。正在初始化调查管理器和浏览器池...")
        manager = InvestigationManager(input_q=navigation_q, output_q=ai_output_q, debug_q=debug_events_q, config=config)
        await manager.initialize(main_browser, playwright) # 传入playwright实例
        logging.info("调查管理器和浏览器池初始化成功。")

        # --------------------------------------------------------------------
        # 步骤 3: 初始化并调度其余所有任务
        # --------------------------------------------------------------------
        debugger = CDPDebugger(output_q=debug_events_q, config=config, playwright=playwright) # 传入playwright实例
        broadcaster = Broadcaster(input_q=ai_output_q, output_queues=[reporter_q, memory_q])
        reporter = ReporterWorker(input_q=reporter_q, config=config)
        memory = MemoryWorker(input_q=memory_q, config=config)

        running_tasks.extend([
            asyncio.create_task(debugger.run(), name="CDPDebugger"),
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

        # 步骤 1: 向所有任务发出取消信号
        for task in running_tasks:
            task.cancel()

        # 步骤 2: 等待所有任务完成取消过程
        logging.info(f"正在等待 {len(running_tasks)} 个任务响应取消信号...")
        results = await asyncio.gather(*running_tasks, return_exceptions=True)
        for i, result in enumerate(results):
            task_name = running_tasks[i].get_name()
            if isinstance(result, asyncio.CancelledError):
                logging.info(f"任务 '{task_name}' 已成功取消。")
            elif isinstance(result, Exception):
                logging.warning(f"任务 '{task_name}' 在关闭时出现异常: {result}")
        
        logging.info("所有后台任务已停止。")

        # 步骤 3: 在所有任务都停止后，安全地关闭资源
        if manager:
            try:
                logging.info("正在关闭调查管理器和浏览器池...")
                await asyncio.wait_for(manager.close(), timeout=15.0)
                logging.info("调查管理器已安全关闭。")
            except asyncio.TimeoutError:
                logging.warning("调查管理器关闭超时。")
            except Exception as e:
                logging.error(f"关闭调查管理器时发生严重错误: {e}", exc_info=True)
        
        # 步骤 4: 最后，关闭Playwright引擎
        if playwright:
            logging.info("正在关闭Playwright引擎...")
            await playwright.stop()
            logging.info("Playwright引擎已关闭。")

        logging.info("Aegis已完全关闭。")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("用户请求关闭。")
