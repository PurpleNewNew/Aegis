import asyncio
import logging
import os
import aiofiles
from asyncio import Queue
from datetime import datetime

class ReporterWorker:
    """
    Pulls final analysis results from a queue and writes them to a 
    Markdown report file asynchronously.
    """

    def __init__(self, input_q: Queue, config: dict):
        """
        Initializes the worker.

        Args:
            input_q: The queue from which to pull final analysis results.
            config: The application configuration dictionary.
        """
        self.input_q = input_q
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.report_dir = self.config['reporter']['output_dir']
        self.report_file_path = os.path.join(self.report_dir, f"aegis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
        self.logger.info(f"Reports will be saved to {self.report_file_path}")

    async def run(self):
        """
        The main loop for the worker.
        It continuously pulls results and writes them to the report file.
        """
        self.logger.info("Reporter Worker is running.")
        try:
            while True:
                result = await self.input_q.get()
                self.logger.info(f"Reporting a finding from {result.get('worker')}")

                # Format the report content
                source_context = result.get('source_context', {})
                # Using triple quotes for the multi-line f-string
                report_content = f"""## Finding from {result.get('worker')}

**Timestamp:** {datetime.now().isoformat()}
**URL:** `{source_context.get('url')}`
**Method:** {source_context.get('method')}

### AI Analysis
```text
{result.get('analysis_text', 'No analysis text provided.')}
```

### Raw Context
<details>
<summary>Click to expand</summary>

```json
{source_context}
```
</details>

---

"""

                try:
                    async with aiofiles.open(self.report_file_path, mode='a', encoding='utf-8') as f:
                        await f.write(report_content)
                    self.logger.info(f"Successfully wrote finding to {self.report_file_path}")
                except Exception as e:
                    self.logger.error(f"Failed to write to report file: {e}")

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("Reporter Worker is shutting down.")
        except Exception as e:
            self.logger.error(f"An error occurred in ReporterWorker: {e}", exc_info=True)