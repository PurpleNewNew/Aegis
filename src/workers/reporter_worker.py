
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
                worker_name = result.get('worker')
                source_context = result.get('source_context', {})
                findings = result.get('findings', [])
                
                self.logger.info(f"收到来自 {worker_name} 的 {len(findings)} 个发现。")

                # 为这批发现创建一个报告片段
                report_segment = f"## 来自 {worker_name} 的分析报告\n\n**源头 URL:** `{source_context.get('initiator_url')}`\n**分析时间:** {datetime.now().isoformat()}\n\n"

                for finding in findings:
                    report_segment += f"""### 漏洞: {finding.get('vulnerability', 'N/A')}\n
- **严重性:** {finding.get('severity', 'N/A')}
- **置信度:** {finding.get('confidence', 'N/A')}

**推理过程:**
```text
{finding.get('reasoning', 'N/A')}
```

**代码证据 (如适用):**
```javascript
{finding.get('evidence', 'N/A')}
```

**修复建议:**
```text
{finding.get('suggestion', 'N/A')}
```
---\n"""
                
                # 将整个片段追加到报告文件中
                try:
                    async with aiofiles.open(self.report_file_path, mode='a', encoding='utf-8') as f:
                        await f.write(report_segment)
                    self.logger.info(f"成功将 {len(findings)} 个发现写入到 {self.report_file_path}")
                except Exception as e:
                    self.logger.error(f"写入报告文件失败: {e}")

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("报告生成器Worker正在关闭。")
        except Exception as e:
            self.logger.error(f"在ReporterWorker中发生错误: {e}", exc_info=True)
