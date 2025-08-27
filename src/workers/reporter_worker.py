import asyncio
import logging
import aiofiles
from pathlib import Path
from asyncio import Queue
from datetime import datetime

class ReporterWorker:
    """
    从队列中提取最终的、完整的调查结果，并将其异步写入一个
    结构化的Markdown报告文件。
    """

    def __init__(self, input_q: Queue, config: dict):
        self.input_q = input_q
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.report_dir = self.config['reporter']['output_dir']

    def _format_finding(self, finding: dict) -> str:
        """将单个发现格式化为Markdown片段。"""
        # 从finding字典中安全地获取每个字段的值
        vulnerability = finding.get('vulnerability', 'N/A')
        severity = finding.get('severity', 'N/A')
        confidence = finding.get('confidence', 'N/A')
        source = finding.get('source', 'N/A')
        interaction_type = finding.get('interaction_type', 'N/A')
        element_selector = finding.get('element_selector', 'N/A')
        description = finding.get('description', '无详细描述')
        attack_vectors = finding.get('attack_vectors', '未提供')
        evidence = finding.get('evidence', '未提供')
        recommendation = finding.get('recommendation', '无修复建议')

        # 构建Markdown字符串
        finding_md = f"""### {vulnerability}\n
- **严重性 (Severity):** `{severity}`
- **置信度 (Confidence):** `{confidence}`
- **来源 (Source):** `{source}`
- **交互详情 (Interaction):** 在`{interaction_type}`事件中，于元素`{element_selector}`处发现。

**描述 (Description):**
> {description}

"""
        # 只有当字段有内容时才添加，避免报告中出现大量空块
        if attack_vectors and attack_vectors != '未提供':
            finding_md += f"""**攻击向量 (Attack Vectors):**\n```text\n{attack_vectors}\n```\n\n"""
        if evidence and evidence != '未提供':
            finding_md += f"""**证据 (Evidence):**\n```text\n{evidence}\n```\n\n"""
        if recommendation and recommendation != '无修复建议':
            finding_md += f"""**修复建议 (Recommendation):**\n```text\n{recommendation}\n```\n\n"""
        finding_md += "---\n"
        return finding_md

    async def run(self):
        self.logger.info("报告生成器Worker正在运行。" )
        try:
            while True:
                result = await self.input_q.get()
                worker_name = result.get('worker')
                source_context = result.get('source_context', {})
                findings = result.get('findings', [])
                architecture_summary = result.get('architecture', '无架构总结')
                initiator_url = source_context.get('initiator_url', 'unknown_target')
                
                self.logger.info(f"收到来自 {worker_name} 对 '{initiator_url}' 的最终报告，包含 {len(findings)} 个发现。" )

                report_content = f"""# Aegis安全审计报告: {initiator_url}\n
**报告生成时间:** {datetime.now().isoformat()}\n
## 架构指纹\n\n```text\n{architecture_summary}\n```\n\n## 漏洞发现详情\n\n"""
                if not findings:
                    report_content += "在此次调查中未发现明确的漏洞。\n"
                else:
                    # 按严重性排序
                    severity_order = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}
                    sorted_findings = sorted(findings, key=lambda x: severity_order.get(x.get('severity'), 0), reverse=True)
                    
                    for finding in sorted_findings:
                        report_content += self._format_finding(finding)
                
                try:
                    # 使用Path和正则表达式确保文件名安全
                    import re
                    safe_filename = re.sub(r'[^\w\-_\.]', '_', initiator_url.replace('https://', '').replace('http://', '')) + ".md"
                    report_file_path = Path(self.report_dir) / safe_filename
                    
                    # 确保目录存在
                    report_file_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    async with aiofiles.open(str(report_file_path), mode='w', encoding='utf-8') as f:
                        await f.write(report_content)
                    self.logger.info(f"成功将报告写入到 {report_file_path}")
                except Exception as e:
                    self.logger.error(f"写入报告文件失败: {e}")

                self.input_q.task_done()

        except asyncio.CancelledError:
            self.logger.info("报告生成器Worker正在关闭。" )
        except Exception as e:
            self.logger.error(f"在ReporterWorker中发生错误: {e}", exc_info=True)