import asyncio
import logging
import yaml
import os
from playwright.async_api import async_playwright, Browser
from asyncio import Queue

# 禁用ChromaDB遥测功能
os.environ['ANONYMIZED_TELEMETRY'] = 'False'

# 配置基础日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# 导入核心组件
from src.controller.cdp_debugger import CDPDebugger
from src.workers.interaction_worker import InteractionWorker

async def main():
    """
    (feature/js_re 分支版)
    初始化并运行Aegis JS逆向分析工具。
    """
    logging.info("Aegis JS逆向分析工具正在启动...")

    # 1. 加载配置
    try:
        with open('config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        logging.info("配置加载成功。")
    except Exception as e:
        logging.error(f"加载或解析配置文件失败: {e}")
        return

    os.makedirs(os.path.dirname(config.get('logging', {}).get('ai_dialogues_file', './logs/ai_dialogues.jsonl')), exist_ok=True)

    # 创建连接CDPDebugger和InteractionWorker的队列
    debug_q = Queue()

    running_tasks = []
    playwright = None
    browser = None
    try:
        # 步骤 1: 启动Playwright并连接到主浏览器（带重试逻辑）
        playwright = await async_playwright().start()
        browser_config = config.get('browser', {})
        endpoint_url = f"http://localhost:{browser_config['remote_debugging_port']}"
        
        while True:
            try:
                browser = await playwright.chromium.connect_over_cdp(endpoint_url)
                logging.info(f"成功连接到主浏览器实例: {endpoint_url}")
                break # 连接成功，跳出循环
            except Exception:
                logging.warning(f"无法连接到浏览器 {endpoint_url}，将在5秒后重试...")
                logging.warning(f"请确保Chrome浏览器已通过 --remote-debugging-port={browser_config['remote_debugging_port']} 参数启动。")
                await asyncio.sleep(5)

        # 步骤 2: 初始化核心组件
        debugger = CDPDebugger(output_q=debug_q, config=config)
        analyzer = InteractionWorker(config=config, debug_q=debug_q)

        running_tasks.extend([
            asyncio.create_task(debugger.run(browser), name="CDPDebugger"),
            asyncio.create_task(analyzer.run(), name="JSAnalyzer"),
        ])

        # 步骤 3: 运行
        logging.info(f"Aegis所有 {len(running_tasks)} 个核心模块已启动。请在主浏览器中操作，触发加密事件...")
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
