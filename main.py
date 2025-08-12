
import asyncio
import logging
import yaml
import os

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Import queue definitions
from src.queues.queues import (
    raw_events_q,
    refined_contexts_q,
    soft_vuln_q,
    reverse_analysis_q,
    final_results_q
)

# Import components
from src.controller.cdp_controller import CDPController
from src.workers.filter_worker import FilterWorker
from src.workers.dispatcher_worker import Dispatcher
from src.workers.ai_soft_worker import AISoftWorker
from src.workers.ai_reverse_worker import AIReverseWorker
from src.workers.reporter_worker import ReporterWorker
from src.workers.memory_worker import MemoryWorker

async def main():
    """
    Initializes and runs the Aegis application components.
    """
    logging.info("Aegis application starting...")

    # --------------------------------------------------------------------
    # Step 1: Load Configuration
    # --------------------------------------------------------------------
    try:
        with open('config.yaml', 'r') as f:
            config = yaml.safe_load(f)
        logging.info("Configuration loaded successfully.")
    except FileNotFoundError:
        logging.error("Configuration file (config.yaml) not found. Please create one.")
        return
    except yaml.YAMLError as e:
        logging.error(f"Error parsing configuration file: {e}")
        return

    # Create reports directory if it doesn't exist
    os.makedirs(config['reporter']['output_dir'], exist_ok=True)

    # A list to hold all our running tasks
    tasks = []

    try:
        # --------------------------------------------------------------------
        # Step 2: Initialize Components
        # --------------------------------------------------------------------
        logging.info("Initializing components...")

        controller = CDPController(output_q=raw_events_q, config=config)
        filter_worker = FilterWorker(input_q=raw_events_q, output_q=refined_contexts_q)
        dispatcher = Dispatcher(input_q=refined_contexts_q, soft_q=soft_vuln_q, reverse_q=reverse_analysis_q)
        ai_soft_worker = AISoftWorker(input_q=soft_vuln_q, output_q=final_results_q, config=config)
        ai_reverse_worker = AIReverseWorker(input_q=reverse_analysis_q, output_q=final_results_q, config=config)
        reporter_worker = ReporterWorker(input_q=final_results_q, config=config)
        memory_worker = MemoryWorker(input_q=final_results_q, config=config)

        # --------------------------------------------------------------------
        # Step 3: Create and schedule tasks for each component
        # --------------------------------------------------------------------
        logging.info("Scheduling worker tasks...")

        tasks.append(asyncio.create_task(controller.run(), name="CDPController"))
        tasks.append(asyncio.create_task(filter_worker.run(), name="FilterWorker"))
        tasks.append(asyncio.create_task(dispatcher.run(), name="Dispatcher"))
        tasks.append(asyncio.create_task(ai_soft_worker.run(), name="AISoftWorker"))
        tasks.append(asyncio.create_task(ai_reverse_worker.run(), name="AIReverseWorker"))
        tasks.append(asyncio.create_task(reporter_worker.run(), name="ReporterWorker"))
        tasks.append(asyncio.create_task(memory_worker.run(), name="MemoryWorker"))

        # --------------------------------------------------------------------
        # Step 4: Run all tasks concurrently
        # --------------------------------------------------------------------
        logging.info("Running all tasks...")
        await asyncio.gather(*tasks)

    except asyncio.CancelledError:
        logging.info("Application shutting down gracefully.")
    finally:
        # Gracefully cancel all running tasks
        for task in tasks:
            if not task.done():
                task.cancel()
        # Wait for all tasks to acknowledge cancellation
        await asyncio.gather(*tasks, return_exceptions=True)
        logging.info("All tasks have been cancelled.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Shutdown requested by user.")

