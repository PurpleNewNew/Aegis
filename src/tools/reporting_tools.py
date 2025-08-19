
"""
用于AI代理与内部状态交互的“伪”工具。
这些函数本身不执行复杂操作，而是作为AI向AgentWorker传递结构化数据的一种方式。
"""
from typing import Literal

def report_finding(
    vulnerability: str, 
    severity: Literal['Critical', 'High', 'Medium', 'Low', 'Informational'], 
    confidence: Literal['High', 'Medium', 'Low'], 
    reasoning: str, 
    suggestion: str, 
    evidence: str = 'N/A'
):
    """
    当你在调查中发现一个具体的、可报告的漏洞时，调用此工具。
    这会将你的发现记录到最终的报告中。
    在报告后，你应继续你的调查，除非你认为所有测试都已完成。
    """
    # 这个函数是空的，因为它的逻辑完全由AgentWorker在检测到此工具被调用时处理。
    pass
