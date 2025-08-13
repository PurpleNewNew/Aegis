import asyncio

# --- 阶段一：捕获与过滤 ---
# (Controller -> Filter)
raw_events_q = asyncio.Queue()

# --- 阶段二：分流与预处理 ---
# (Filter -> Correlator) - 用于网络请求事件
requests_q = asyncio.Queue()
# (Filter -> Summarizer) - 用于需要AI摘要的JS文件
js_to_summarize_q = asyncio.Queue()

# --- 阶段三：关联与打包 ---
# (Summarizer -> Correlator) - 用于携带了AI摘要的JS文件
summarized_js_q = asyncio.Queue()
# (Correlator -> CorrelationWorker) - 包含了请求和JS摘要的完整上下文包
analysis_packages_q = asyncio.Queue()

# --- 阶段四：最终分析与输出 ---
# (CorrelationWorker -> Broadcaster) - 最终的漏洞发现结果
ai_output_q = asyncio.Queue()
# (Broadcaster -> Reporter/Memory) - 广播后的专属队列
reporter_q = asyncio.Queue()
memory_q = asyncio.Queue()