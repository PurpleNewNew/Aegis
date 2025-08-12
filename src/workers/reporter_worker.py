
import asyncio
import logging
import os
import aiofiles
from asyncio import Queue
from datetime import datetime

class ReporterWorker:
    """
    从队列中提取最终的分析结果，并将其异步写入一个
    Markdown报告文件。
    """

    def __init__(self, input_q: Queue, config: dict):
        """
        初始化Worker。

        Args:
            input_q: 用于提取最终分析结果的输入队列。
            config: 应用程序的配置字典。
        """
        self.input_q = input_q
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.report_dir = self.config['reporter']['output_dir']
        self.report_file_path = os.path.join(self.report_dir, f"aegis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
        self.logger.info(f"报告将被保存到 {self.report_file_path}")

    async def run(self):
        """
        Worker的主循环。
        它持续地提取结果并将其写入报告文件。
        """
        self.logger.info("报告生成器Worker正在运行。")
        try:
            while True:
                result = await self.input_q.get()
                self.logger.info(f"正在报告一个来自 {result.get('worker')} 的发现。")

                # 格式化报告内容
                source_context = result.get('source_context', {})
                # 使用三引号以支持多行f-string
                report_content = f"""## 来自 {result.get('worker')} 的发现\n\n**时间戳:** {datetime.now().isoformat()}\n**URL:** `{source_context.get('url')}`\n**方法:** {source_context.get('method')}\n\n### AI 分析\n```text\n{result.get('analysis_text', '未提供分析文本。')}\n```\n\n### 原始上下文\n<details>\n<summary>点击展开</summary>\n\n```json\n{source_context}\n```\n</details>\n\n---\n\n"""

                try:
                    async with aiofiles.open(self.report_file_path, mode='a', encoding='utf-8') as f:
                        await f.write(report_content)
                    self.logger.info(f"成功将发现写入到 {self.report_file_path}")
                except Exception as e:
                    self.logger.error(f"写入报告文件失败: {e}")

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("报告生成器Worker正在关闭。")
        except Exception as e:
            self.logger.error(f"在ReporterWorker中发生错误: {e}", exc_info=True)
