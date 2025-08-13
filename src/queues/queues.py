
import asyncio

# 原始事件队列 (Controller -> Filter)
raw_events_q = asyncio.Queue()

# 已过滤事件队列 (Filter -> Correlator)
filtered_events_q = asyncio.Queue()

# 分析包队列 (Correlator -> HolisticAI)
analysis_packages_q = asyncio.Queue()

# AI分析结果的统一出口 (HolisticAI -> Broadcaster)
ai_output_q = asyncio.Queue()

# 广播后的专属队列
reporter_q = asyncio.Queue() # 报告器的专属队列
memory_q = asyncio.Queue()   # 记忆器的专属队列
