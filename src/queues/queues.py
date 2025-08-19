
import asyncio

# --- 输入与调度 ---
# (CDPController -> InvestigationManager)
navigation_q = asyncio.Queue()
# (CDPDebugger -> AgentWorker)
debug_events_q = asyncio.Queue()

# --- 结果输出 ---
# (AgentWorker -> Broadcaster)
ai_output_q = asyncio.Queue()
# (Broadcaster -> Reporter/Memory)
reporter_q = asyncio.Queue()
memory_q = asyncio.Queue()

# --- 系统状态与协调 ---
# (CDPController -> main)
controller_status_q = asyncio.Queue(maxsize=1)
