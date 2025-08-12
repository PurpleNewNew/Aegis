
import asyncio
import logging
import yaml
import os

# 配置基础日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# 导入队列定义
from src.queues.queues import (
    raw_events_q,
    refined_contexts_q, # 现在是文件写入器的输入
    soft_vuln_q,
    reverse_analysis_q,
    ai_output_q,
    reporter_q,
    memory_q
)

# 导入组件
from src.controller.cdp_controller import CDPController
from src.workers.filter_worker import FilterWorker
from src.workers.jsonl_writer_worker import JsonlWriterWorker # 新增
from src.workers.jsonl_reader_worker import JsonlReaderWorker # 新增
from src.workers.dispatcher_worker import Dispatcher
from src.workers.ai_soft_worker import AISoftWorker
from src.workers.ai_reverse_worker import AIReverseWorker
from src.workers.broadcaster import Broadcaster
from src.workers.reporter_worker import ReporterWorker
from src.workers.memory_worker import MemoryWorker

async def main():
    """
    初始化并运行Aegis应用的所有组件。
    """
    logging.info("Aegis应用正在启动...")

    # --------------------------------------------------------------------
    # 步骤 1: 加载配置
    # --------------------------------------------------------------------
    try:
        with open('config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        logging.info("配置加载成功。")
    except FileNotFoundError:
        logging.error("配置文件 (config.yaml) 未找到。请创建一个。")
        return
    except yaml.YAMLError as e:
        logging.error(f"解析配置文件时出错: {e}")
        return

    # 如果目录不存在，则创建它们
    os.makedirs(config['reporter']['output_dir'], exist_ok=True)
    os.makedirs(os.path.dirname(config['logging']['ai_dialogues_file']), exist_ok=True)
    os.makedirs("data", exist_ok=True)
    capture_file_path = "data/capture.jsonl"

    # 这个队列将连接文件读取器和调度器
    analysis_tasks_q = asyncio.Queue()

    # 用于存放所有运行任务的列表
    tasks = []

    try:
        # --------------------------------------------------------------------
        # 步骤 2: 使用文件缓冲架构初始化组件
        # --------------------------------------------------------------------
        logging.info("正在初始化组件...")

        # --- 捕获流水线 ---
        controller = CDPController(output_q=raw_events_q, config=config)
        filter_worker = FilterWorker(input_q=raw_events_q, output_q=refined_contexts_q, config=config)
        jsonl_writer = JsonlWriterWorker(input_q=refined_contexts_q, file_path=capture_file_path)

        # --- 分析流水线 ---
        jsonl_reader = JsonlReaderWorker(output_q=analysis_tasks_q, file_path=capture_file_path)
        dispatcher = Dispatcher(input_q=analysis_tasks_q, soft_q=soft_vuln_q, reverse_q=reverse_analysis_q)
        ai_soft_worker = AISoftWorker(input_q=soft_vuln_q, output_q=ai_output_q, config=config)
        ai_reverse_worker = AIReverseWorker(input_q=reverse_analysis_q, output_q=ai_output_q, config=config)
        broadcaster = Broadcaster(input_q=ai_output_q, output_queues=[reporter_q, memory_q])
        reporter_worker = ReporterWorker(input_q=reporter_q, config=config)
        memory_worker = MemoryWorker(input_q=memory_q, config=config)

        # --------------------------------------------------------------------
        # 步骤 3: 为每个组件创建并调度任务
        # --------------------------------------------------------------------
        logging.info("正在调度Worker任务...")
        
        # 捕获任务
        tasks.append(asyncio.create_task(controller.run(), name="CDPController"))
        tasks.append(asyncio.create_task(filter_worker.run(), name="FilterWorker"))
        tasks.append(asyncio.create_task(jsonl_writer.run(), name="JsonlWriterWorker"))

        # 分析任务
        tasks.append(asyncio.create_task(jsonl_reader.run(), name="JsonlReaderWorker"))
        tasks.append(asyncio.create_task(dispatcher.run(), name="Dispatcher"))
        tasks.append(asyncio.create_task(ai_soft_worker.run(), name="AISoftWorker"))
        tasks.append(asyncio.create_task(ai_reverse_worker.run(), name="AIReverseWorker"))
        tasks.append(asyncio.create_task(broadcaster.run(), name="Broadcaster"))
        tasks.append(asyncio.create_task(reporter_worker.run(), name="ReporterWorker"))
        tasks.append(asyncio.create_task(memory_worker.run(), name="MemoryWorker"))

        # --------------------------------------------------------------------
        # 步骤 4: 并发运行所有任务
        # --------------------------------------------------------------------
        logging.info("正在运行所有任务...")
        await asyncio.gather(*tasks)

    except asyncio.CancelledError:
        logging.info("应用正在优雅地关闭。")
    finally:
        # 优雅地取消所有正在运行的任务
        for task in tasks:
            if not task.done():
                task.cancel()
        # 等待所有任务确认取消
        await asyncio.gather(*tasks, return_exceptions=True)
        logging.info("所有任务已被取消。")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("用户请求关闭。")
