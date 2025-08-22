import asyncio
import logging
import yaml
import os
from playwright.async_api import async_playwright

# 导入队列管理器
from src.queues.queue_manager import QueueManager, QueueType

# 禁用ChromaDB遥测功能
os.environ['ANONYMIZED_TELEMETRY'] = 'False'

# 配置基础日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# 导入核心组件
from src.controller.cdp_debugger import CDPDebugger
from src.workers.interaction_worker import InteractionWorker
from src.data.data_hub import get_data_hub, DataHub

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

    # 初始化队列管理器
    queue_manager = QueueManager(config)
    debug_q = queue_manager.get_queue(QueueType.DEBUG_EVENTS)
    network_data_q = queue_manager.get_queue(QueueType.NETWORK_DATA)
    js_hook_events_q = queue_manager.get_queue(QueueType.JS_HOOK_EVENTS)

    # 初始化数据枢纽
    data_hub = get_data_hub()

    # 启动队列处理任务
    queue_tasks = []
    queue_tasks.append(asyncio.create_task(data_hub.process_queue(debug_q, 'cdp_events')))
    queue_tasks.append(asyncio.create_task(data_hub.process_queue(network_data_q, 'network_data')))
    queue_tasks.append(asyncio.create_task(data_hub.process_queue(js_hook_events_q, 'js_hook_events')))

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
        analyzer = InteractionWorker(config=config, debug_q=debug_q, js_hook_events_q=js_hook_events_q)
        debugger = CDPDebugger(output_q=debug_q, network_data_q=network_data_q, config=config, interaction_worker=analyzer)

        running_tasks.extend([
            asyncio.create_task(debugger.run(browser), name="CDPDebugger"),
            asyncio.create_task(analyzer.run(), name="JSAnalyzer"),
        ])

        # 步骤 3: 运行
        logging.info(f"Aegis所有 {len(running_tasks)} 个核心模块已启动。请在主浏览器中操作，触发加密事件...")
        await asyncio.gather(*running_tasks, *queue_tasks)

    except asyncio.CancelledError:
        logging.info("应用主任务收到关闭信号...")
    finally:
        logging.info("正在优雅地关闭所有服务...")

        # 收集所有任务
        all_tasks = running_tasks + queue_tasks
        
        # 取消所有未完成的任务
        for task in all_tasks:
            if not task.done():
                task.cancel()
        
        # 等待所有任务完成
        results = await asyncio.gather(*all_tasks, return_exceptions=True)
        
        # 处理结果
        for i, (task, result) in enumerate(zip(all_tasks, results)):
            task_name = task.get_name() if hasattr(task, 'get_name') else f"Task-{i}"
            if isinstance(result, asyncio.CancelledError):
                logging.info(f"任务 '{task_name}' 已成功取消。")
            elif isinstance(result, Exception):
                logging.warning(f"任务 '{task_name}' 在关闭时出现异常: {result}")
        
        logging.info("所有后台任务已停止。")

        await data_hub.shutdown()
        
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
