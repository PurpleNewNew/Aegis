import asyncio
import logging
import yaml
import os

# 配置基础日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# 导入最终架构所需的队列
from src.queues.queues import (
    raw_events_q,
    requests_q,
    js_to_summarize_q,
    summarized_js_q,
    analysis_packages_q,
    ai_output_q,
    reporter_q,
    memory_q
)

# 导入最终架构的核心组件
from src.controller.cdp_controller import CDPController
from src.workers.filter_worker import FilterWorker
from src.workers.js_summarizer_worker import JSSummarizerWorker
from src.workers.context_correlator import ContextCorrelator
from src.workers.correlation_worker import CorrelationWorker
from src.workers.broadcaster import Broadcaster
from src.workers.reporter_worker import ReporterWorker
from src.workers.memory_worker import MemoryWorker

async def main():
    """
    初始化并运行Aegis应用的所有组件。
    """
    logging.info("Aegis应用正在启动 (v3.0 - 摘要-关联架构)...")

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

    os.makedirs(config['reporter']['output_dir'], exist_ok=True)
    os.makedirs(os.path.dirname(config['logging']['ai_dialogues_file']), exist_ok=True)

    tasks = []

    try:
        # --------------------------------------------------------------------
        # 步骤 2: 初始化最终架构的组件
        # --------------------------------------------------------------------
        logging.info("正在初始化所有Worker...")

        controller = CDPController(output_q=raw_events_q, config=config)
        filter_worker = FilterWorker(input_q=raw_events_q, request_q=requests_q, js_q=js_to_summarize_q, config=config)
        
        # AI预处理阶段
        summarizer = JSSummarizerWorker(input_q=js_to_summarize_q, output_q=summarized_js_q, config=config)
        
        # 上下文关联阶段
        correlator = ContextCorrelator(request_q=requests_q, summarized_js_q=summarized_js_q, output_q=analysis_packages_q)
        
        # 最终分析阶段
        correlation_analyzer = CorrelationWorker(input_q=analysis_packages_q, output_q=ai_output_q, config=config)
        
        # 结果分发与输出
        broadcaster = Broadcaster(input_q=ai_output_q, output_queues=[reporter_q, memory_q])
        reporter = ReporterWorker(input_q=reporter_q, config=config)
        memory = MemoryWorker(input_q=memory_q, config=config)

        # --------------------------------------------------------------------
        # 步骤 3: 调度所有任务
        # --------------------------------------------------------------------
        logging.info("正在调度所有Worker任务...")
        
        tasks.extend([
            asyncio.create_task(controller.run(), name="CDPController"),
            asyncio.create_task(filter_worker.run(), name="FilterWorker"),
            asyncio.create_task(summarizer.run(), name="JSSummarizerWorker"),
            asyncio.create_task(correlator.run(), name="ContextCorrelator"),
            asyncio.create_task(correlation_analyzer.run(), name="CorrelationWorker"),
            asyncio.create_task(broadcaster.run(), name="Broadcaster"),
            asyncio.create_task(reporter.run(), name="ReporterWorker"),
            asyncio.create_task(memory.run(), name="MemoryWorker")
        ])

        # --------------------------------------------------------------------
        # 步骤 4: 并发运行所有任务
        # --------------------------------------------------------------------
        logging.info("正在运行所有任务...")
        await asyncio.gather(*tasks)

    except asyncio.CancelledError:
        logging.info("应用正在优雅地关闭。")
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        logging.info("所有任务已被取消。")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("用户请求关闭。")