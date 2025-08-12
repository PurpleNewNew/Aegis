
import asyncio

# ① 原始事件队列
raw_events_q = asyncio.Queue()

# ② 精炼上下文队列
refined_contexts_q = asyncio.Queue()

# ③-a Soft Queue - 软漏洞分析任务队列
soft_vuln_q = asyncio.Queue()

# ③-b Reverse Queue - 逆向分析任务队列
reverse_analysis_q = asyncio.Queue()

# ④ 最终结果队列
final_results_q = asyncio.Queue()
