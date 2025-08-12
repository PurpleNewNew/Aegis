import asyncio

# ① 原始事件队列
raw_events_q = asyncio.Queue()

# ② 精炼上下文队列 (现在是文件写入器的输入)
refined_contexts_q = asyncio.Queue()

# ③-a 软漏洞分析任务队列
soft_vuln_q = asyncio.Queue()

# ③-b 逆向分析任务队列
reverse_analysis_q = asyncio.Queue()

# ③-c JS Analysis Queue - JS文件分析任务队列
js_analysis_q = asyncio.Queue()

# ④ AI分析结果的统一出口
ai_output_q = asyncio.Queue()

# ⑤ 广播后的专属队列
reporter_q = asyncio.Queue() # 报告器的专属队列
memory_q = asyncio.Queue()   # 记忆器的专属队列