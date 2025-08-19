"""
AI对话日志记录模块
用于记录与LLM的所有交互，便于调试和审计
"""

import json
import aiofiles
from datetime import datetime
from typing import Any
import os


async def log_ai_dialogue(prompt: str, response: str, log_file_path: str) -> None:
    """
    异步记录AI对话到JSONL文件
    
    Args:
        prompt: 发送给AI的提示词
        response: AI的响应
        log_file_path: 日志文件路径
    """
    try:
        # 确保日志目录存在
        os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
        
        # 构建日志条目
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "prompt": prompt,
            "response": response,
            "prompt_length": len(prompt),
            "response_length": len(response)
        }
        
        # 异步追加到文件
        async with aiofiles.open(log_file_path, mode='a', encoding='utf-8') as f:
            await f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
            
    except Exception as e:
        # 日志记录失败不应该影响主流程，但应打印错误
        print(f"[ERROR] Failed to log AI dialogue: {e}")


async def rotate_log_if_needed(log_file_path: str, max_size_mb: int = 10) -> None:
    """
    如果日志文件过大，进行轮转
    
    Args:
        log_file_path: 日志文件路径
        max_size_mb: 最大文件大小（MB）
    """
    try:
        if os.path.exists(log_file_path):
            size_mb = os.path.getsize(log_file_path) / (1024 * 1024)
            if size_mb > max_size_mb:
                # 重命名旧文件
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = log_file_path.replace('.jsonl', f'_{timestamp}.jsonl')
                os.rename(log_file_path, backup_path)
                print(f"Log rotated: {log_file_path} -> {backup_path}")
    except Exception as e:
        print(f"Warning: Failed to rotate log: {e}")
