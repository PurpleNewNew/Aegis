
import asyncio
import logging
import yaml
import os

# 配置基础日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# 导入队列定义
from src.queues.queues import (
    raw_events_q,
    filtered_events_q,
    analysis_packages_q,
    ai_output_q,
    reporter_q,
    memory_q
)

# 导入新架构的核心组件
from src.controller.cdp_controller import CDPController
from src.workers.filter_worker import FilterWorker
from src.workers.context_correlator import ContextCorrelator
from src.workers.holistic_analysis_worker import HolisticAnalysisWorker
from src.workers.broadcaster import Broadcaster
from src.workers.reporter_worker import ReporterWorker
from src.workers.memory_worker import MemoryWorker

async def main():
    """
    初始化并运行Aegis应用的所有组件。
    """
    logging.info("Aegis应用正在启动 (v2.0 - 上下文感知架构)...")

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

    # 用于存放所有运行任务的列表
    tasks = []

    try:
        # --------------------------------------------------------------------
        # 步骤 2: 初始化新架构的组件
        # --------------------------------------------------------------------
        logging.info("正在初始化组件...")

        # --- 流水线定义 ---
        controller = CDPController(output_q=raw_events_q, config=config)
        filter_worker = FilterWorker(input_q=raw_events_q, output_q=filtered_events_q, config=config)
        correlator = ContextCorrelator(input_q=filtered_events_q, output_q=analysis_packages_q)
        holistic_analyzer = HolisticAnalysisWorker(input_q=analysis_packages_q, output_q=ai_output_q, config=config)
        broadcaster = Broadcaster(input_q=ai_output_q, output_queues=[reporter_q, memory_q])
        reporter = ReporterWorker(input_q=reporter_q, config=config)
        memory = MemoryWorker(input_q=memory_q, config=config)

        # --------------------------------------------------------------------
        # 步骤 3: 为每个组件创建并调度任务
        # --------------------------------------------------------------------
        logging.info("正在调度Worker任务...")
        
        tasks.append(asyncio.create_task(controller.run(), name="CDPController"))
        tasks.append(asyncio.create_task(filter_worker.run(), name="FilterWorker"))
        tasks.append(asyncio.create_task(correlator.run(), name="ContextCorrelator"))
        tasks.append(asyncio.create_task(holistic_analyzer.run(), name="HolisticAnalysisWorker"))
        tasks.append(asyncio.create_task(broadcaster.run(), name="Broadcaster"))
        tasks.append(asyncio.create_task(reporter.run(), name="ReporterWorker"))
        tasks.append(asyncio.create_task(memory.run(), name="MemoryWorker"))

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
