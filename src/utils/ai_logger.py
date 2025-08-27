"""
AI对话日志记录模块
用于记录与LLM的所有交互，便于调试和审计
"""

import json
import aiofiles
from datetime import datetime
from typing import Any
import os
import logging
from .security_utils import SecurityUtils

logger = logging.getLogger(__name__)


async def log_ai_dialogue(prompt: str, response: str, log_file_path: str) -> None:
    """
    异步记录AI对话到JSONL文件
    
    Args:
        prompt: 发送给AI的提示词
        response: AI的响应
        log_file_path: 日志文件路径
    """
    try:
        # 验证文件路径安全性
        safe_log_path = SecurityUtils.validate_file_path(log_file_path)
        
        # 确保日志目录存在（使用安全创建方法）
        log_dir = os.path.dirname(safe_log_path)
        SecurityUtils.create_safe_directory(log_dir)
        
        # 构建日志条目
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "prompt": prompt,
            "response": response,
            "prompt_length": len(prompt),
            "response_length": len(response)
        }
        
        # 异步追加到文件
        async with aiofiles.open(safe_log_path, mode='a', encoding='utf-8') as f:
            await f.write(json.dumps(log_entry, ensure_ascii=False) + '\n')
            
    except (OSError, ValueError) as e:
        logger.error(f"Failed to log AI dialogue due to file/permission error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error logging AI dialogue: {e}")


async def rotate_log_if_needed(log_file_path: str, max_size_mb: int = 10) -> None:
    """
    如果日志文件过大，进行轮转
    
    Args:
        log_file_path: 日志文件路径
        max_size_mb: 最大文件大小（MB）
    """
    try:
        # 验证文件路径安全性
        safe_log_path = SecurityUtils.validate_file_path(log_file_path)
        
        if os.path.exists(safe_log_path):
            size_mb = os.path.getsize(safe_log_path) / (1024 * 1024)
            if size_mb > max_size_mb:
                # 重命名旧文件
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = safe_log_path.replace('.jsonl', f'_{timestamp}.jsonl')
                os.rename(safe_log_path, backup_path)
                logger.info(f"Log rotated: {safe_log_path} -> {backup_path}")
    except (OSError, ValueError) as e:
        logger.error(f"Failed to rotate log due to file/permission error: {e}")
    except Exception as e:
        logger.error(f"Unexpected error rotating log: {e}")
