
import asyncio
from src.utils.bounded_queue import create_queue

# --- 输入与调度 ---
# (CDPController -> InvestigationManager)
navigation_q = create_queue(maxsize=500, name="navigation_q")
# (CDPDebugger -> AgentWorker)
debug_events_q = create_queue(maxsize=1000, name="debug_events_q")

# --- 结果输出 ---
# (AgentWorker -> Broadcaster)
ai_output_q = create_queue(maxsize=500, name="ai_output_q")
# (Broadcaster -> Reporter/Memory)
reporter_q = create_queue(maxsize=200, name="reporter_q")
memory_q = create_queue(maxsize=200, name="memory_q")

# --- 系统状态与协调 ---
# (CDPController -> main)
controller_status_q = create_queue(maxsize=1, name="controller_status_q")
