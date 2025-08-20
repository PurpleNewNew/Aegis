import json
from typing import List, Dict, Any, Optional

# AgentWorker可用的工具定义
AVAILABLE_TOOLS = {
    "navigate": {
        "description": "导航到一个新的URL地址。",
        "args": {"url": "(string) 目标URL地址。"}
    },
    "get_web_content": {
        "description": "获取当前页面的HTML内容，用于理解页面结构。",
        "args": {}
    },
    "get_interactive_elements": {
        "description": "获取页面上所有可交互元素的列表，以便进行点击或输入操作。",
        "args": {}
    },
    "click_element": {
        "description": "点击一个由选择器（selector）指定的页面元素。",
        "args": {"selector": "(string) 目标元素的CSS选择器。"}
    },
    "input_text": {
        "description": "在一个由选择器（selector）指定的输入框中输入文本。",
        "args": {"selector": "(string) 目标输入框的CSS选择器。", "text": "(string) 要输入的文本。"}
    },
    "report_finding": {
        "description": "当你确信发现了一个具体、可报告的漏洞时，调用此工具。",
        "args": {
            "vulnerability": "(string) 漏洞的简短名称",
            "severity": "(string) 严重性，选项: 'Critical', 'High', 'Medium', 'Low', 'Informational'",
            "confidence": "(string) 置信度，选项: 'High', 'Medium', 'Low'",
            "reasoning": "(string) 详细的推理过程",
            "suggestion": "(string) 修复建议",
            "evidence": "(string, optional) 导致你判断的直接证据代码或文本"
        }
    },
    "finish_investigation": {
        "description": "当你认为对当前页面的所有功能点和线索的测试都已充分完成时，调用此工具来结束调查。",
        "args": {"summary": "(string) 总结你的发现和调查结论。"}
    }
}

def get_interaction_analysis_prompt(interaction_type: str, snapshot: Dict[str, Any], analysis_results: Dict[str, Any], goal: str, reasoning_level: str = 'high') -> str:
    """
    构建用于交互分析的提示词，专门分析用户交互点的安全风险。
    """
    prompt_lines = [
        "你是一名专业的Web安全分析师，专门分析用户交互点的安全风险。",
        f"**交互类型**: {interaction_type}",
        f"**分析目标**: {goal}",
        "",
        "**交互快照信息**:",
        f"- URL: {snapshot.get('url', 'N/A')}",
        f"- 页面标题: {snapshot.get('title', 'N/A')}",
    ]

    if reasoning_level in ['medium', 'high']:
        prompt_lines.append("\n**SAST扫描结果**:")
        sast_results = snapshot.get('sast_results', {})
        if sast_results and any(findings for findings in sast_results.values()):
            for tool_name, findings in sast_results.items():
                if findings:
                    prompt_lines.append(f"- **{tool_name}**:")
                    for finding in findings[:3]:
                        prompt_lines.append(f"  - {json.dumps(finding, ensure_ascii=False)}")
        else:
            prompt_lines.append("无SAST发现")

    if reasoning_level == 'high':
        prompt_lines.append("\n**深度动态分析情报**: (这是我们通过模拟交互、注入探针等方式获得的、最有价值的证据)")
        network_analysis = analysis_results.get('network_packet_analysis')
        if network_analysis and network_analysis.get('api_calls'):
            prompt_lines.append(f"- **网络API调用分析**: (共发现 {network_analysis.get('summary',{}).get('xhr_fetch_requests', 0)} 个API调用)")
            for api_call in network_analysis['api_calls'][:2]:
                prompt_lines.append(f"  - **API**: `{api_call.get('method')} {api_call.get('url')}`")
                if api_call.get('potential_issues'):
                    prompt_lines.append(f"    - **潜在问题**: {', '.join(api_call['potential_issues'])}")
        else:
            prompt_lines.append("- **网络API调用分析**: 未捕获到API调用。")

        iast_findings = analysis_results.get('iast_findings', [])
        if iast_findings:
            prompt_lines.append("- **IAST运行时警报**: (捕获到高风险JS调用)")
            for finding in iast_findings[:2]:
                if finding.get('type') == 'cdp_event':
                    prompt_lines.append(f"  - **[CDP]** 在`{finding.get('trigger')}`事件中，函数`{finding.get('function_name')}`被调用。捕获变量: {json.dumps(finding.get('variables', {}))}")
                elif finding.get('type') == 'iast_event':
                    prompt_lines.append(f"  - **[Hook]** 危险函数`{finding.get('sink')}`被调用，传入值: {finding.get('value')}")

    prompt_lines.extend([
        "",
        "**分析要求**:",
        "1. 综合以上所有信息，分析此交互点是否存在特定的安全风险。",
        "2. 你的分析必须基于上面提供的具体情报。",
        "3. 提供具体的安全建议。",
        "",
        "**输出格式**:",
        "请以JSON格式返回分析结果。",
    ])

    if reasoning_level == 'high':
        prompt_lines.extend([
            "```json",
            '{"risk_assessment": "风险等级", "analysis_summary": "总结", "security_recommendations": ["建议1"], "potential_attack_vectors": ["攻击向量1"]}',
            "```",
        ])
    else:
        prompt_lines.extend([
            "```json",
            '{"risk_assessment": "风险等级", "analysis_summary": "总结"}',
            "```",
        ])

    prompt_lines.extend([
        "",
        "**重要提醒**: 你的回复必须仅仅是JSON对象，不包含任何其他文本。",
    ])
    
    return "\n".join(prompt_lines)

def get_agent_reasoning_prompt(goal: str, history: List[Dict[str, Any]], observation: str, sast_results: Dict[str, List[str]], iast_findings: List[Dict[str, str]], network_analysis: Optional[Dict[str, Any]], long_term_memories: List[str], reasoning_level: str = 'high') -> str:
    """
    构建一个提示词，用于驱动“AI指挥官”进行思考和决策。
    """
    tools_description = ""
    for name, details in AVAILABLE_TOOLS.items():
        tools_description += f"- `{name}`: {details['description']}\n"
        if details['args']:
            tools_description += "  参数:\n"
            for arg_name, arg_desc in details['args'].items():
                tools_description += f"    - `{arg_name}`: {arg_desc}\n"

    prompt_lines = [
        "你是一名顶级的安全测试总指挥。",
        f"**总任务目标**: {goal}",
        "",
        "**可用交互工具清单**:",
        tools_description,
        "",
    ]

    if reasoning_level in ['medium', 'high']:
        if history:
            prompt_lines.append("\n**历史操作与观察**:")
            for item in history[-2:]:
                prompt_lines.append(f"- **决策**: {item['thought']} -> **动作**: `{item['tool_call']['name']}` -> **结果**: {str(item['observation'])[:300]}")
        
        prompt_lines.append("\n**自动化静态扫描(SAST)初步线索**:")
        if sast_results and any(findings for findings in sast_results.values()):
            for tool_name, findings in sast_results.items():
                if findings:
                    prompt_lines.append(f"- **`{tool_name}`** 发现了 {len(findings)} 个线索。")
        else:
            prompt_lines.append("无任何发现。")

    if reasoning_level == 'high':
        prompt_lines.append("\n**交互式运行时(IAST)警报**:")
        if iast_findings:
            prompt_lines.append("**警告**: 捕获到以下高风险运行时事件！请重点分析！")
            for finding in iast_findings:
                if finding.get('type') == 'cdp_event':
                    prompt_lines.append(f"- **[CDP调试器]** 在`{finding.get('trigger')}`事件中，函数`{finding.get('function_name')}`被调用。捕获到的变量: {json.dumps(finding.get('variables', {}))}")
                elif finding.get('type') == 'iast_event':
                    prompt_lines.append(f"- **[JS Hook]** 危险函数`{finding.get('sink')}`被调用，传入的值: {finding.get('value')}")
        else:
            prompt_lines.append("无任何运行时警报。")

        prompt_lines.append("\n**网络流量分析(上一步操作触发)**:")
        if network_analysis and network_analysis.get('api_calls'):
            prompt_lines.append(f"- **API调用**: (共发现 {network_analysis.get('summary',{}).get('xhr_fetch_requests', 0)} 个API调用)")
            for api_call in network_analysis['api_calls'][:2]:
                prompt_lines.append(f"  - `{api_call.get('method')} {api_call.get('url')}`")
                if api_call.get('potential_issues'):
                    prompt_lines.append(f"    - **潜在问题**: {', '.join(api_call['potential_issues'])}")
        else:
            prompt_lines.append("- 未捕获到API调用。")

    prompt_lines.append(f"\n**当前的动态观察结果**:\n```\n{observation}\n```")
    
    prompt_lines.extend([
        "",
        "**你的任务**:",
        "1.  **思考**: 基于当前所有情报，用一句话总结下一步测试思路。",
        "2.  **决策**: 从工具清单中选择一个工具来执行。",
        "",
        "**输出要求**: 你的回答**必须**是JSON对象，包含 `thought` 和 `tool_call` 两个键。",
        "**JSON输出示例**: ",
        '```json\n{ "thought": "点击注册按钮探索功能", "tool_call": { "name": "click_element", "args": { "selector": "[data-aegis-id=\"aegis-el-7\"]" } } }\n```',
        "**关键指令**: 你的整个回复**必须**仅仅是JSON对象，不包含任何其他文本。"
    ])

    return "\n".join(prompt_lines)
