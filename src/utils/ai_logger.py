import logging
import json
import aiofiles
from datetime import datetime

async def log_ai_dialogue(prompt: str, response: str, log_file_path: str):
    """
    将AI的提示及其对应的响应异步记录到一个.jsonl文件中。

    Args:
        prompt: 发送给AI的提示。
        response: 从AI收到的原始响应。
        log_file_path: .jsonl日志文件的路径。
    """
    logger = logging.getLogger("AILogger")
    # --- 实时打印到控制台 ---
    print("\n" + "-" * 25 + " AI 对话开始 " + "-" * 25)
    print(f"[🤖 PROMPT] -> 发送给AI的提示 (部分):\n{prompt[:400]}...\n")
    print(f"[🧠 RESPONSE] <- 来自AI的回复:\n{response}\n")
    print("-" * 27 + " AI 对话结束 " + "-" * 27 + "\n")

    # --- 写入到日志文件 ---
    try:
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'prompt': prompt,
            'response': response
        }
        async with aiofiles.open(log_file_path, mode='a', encoding='utf-8') as f:
            # 使用ensure_ascii=False来正确处理中文字符
            await f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
    except Exception as e:
        logger.error(f"向 {log_file_path} 记录AI对话失败: {e}")