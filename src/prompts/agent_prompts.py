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
    },
    "analyze_js_crypto": {
        "description": "当检测到加密函数或需要分析JavaScript代码的安全机制时使用此工具。",
        "args": {
            "function_name": "(string, optional) 要分析的函数名",
            "focus": "(string) 分析重点：'algorithm'（算法识别）、'security'（安全机制）、'vulnerability'（漏洞检测）或 'comprehensive'（综合分析）"
        }
    },
    "detect_crypto_functions": {
        "description": "扫描当前页面查找所有加密和安全相关的JavaScript函数。",
        "args": {}
    },
    "analyze_network_crypto": {
        "description": "分析网络请求中的加密数据传输模式。",
        "args": {}
    }
}

def get_agent_reasoning_prompt(goal: str, history: List[Dict[str, Any]], observation: str, sast_results: Dict[str, List[str]], iast_findings: List[Dict[str, str]], network_analysis: Optional[Dict[str, Any]], long_term_memories: List[str], reasoning_level: str = 'high', parallel_mode: bool = False, available_browsers: int = 1) -> str:
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
        "你是一名顶级的安全测试总指挥，具备JavaScript逆向工程和加密分析能力。",
        f"**总任务目标**: {goal}",
        "",
    ]
    
    if parallel_mode and available_browsers > 1:
        prompt_lines.extend([
            f"**🚀 并行测试模式**: 你当前可以控制 {available_browsers} 个影子浏览器同时进行测试！",
            "- 你可以设计并行测试策略，同时测试多个功能点",
            "- 例如：一个浏览器测试登录，另一个测试注册；或同时测试不同的表单",
            "- 系统会自动分配任务到不同的浏览器",
            "",
        ])
    
    prompt_lines.extend([
        "**可用交互工具清单**:",
        tools_description,
        "",
        "**JS逆向分析能力**:",
        "- 你具备JavaScript加密分析和逆向工程能力",
        "- 使用 `analyze_js_crypto` 深入分析加密函数",
        "- 使用 `detect_crypto_functions` 扫描页面中的所有加密相关函数",
        "- 使用 `analyze_network_crypto` 分析网络加密传输",
        "",
    ])

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
        "**JS逆向触发条件**:",
        "- 当发现加密函数名（encrypt/decrypt/hash等）时，使用JS逆向工具分析",
        "- 当检测到混淆的JavaScript代码时，使用JS逆向工具分析",
        "- 当发现网络请求中有加密数据时，分析加密模式",
        "- 当IAST检测到危险函数调用时，深入分析相关代码",
        "",
        "**输出要求**: 你的回答**必须**是JSON对象，包含 `thought` 和 `tool_call` 两个键。",
        "**JSON输出示例**: ",
        '```json\n{ "thought": "检测到加密函数，使用JS逆向分析", "tool_call": { "name": "analyze_js_crypto", "args": { "function_name": "encryptData" } } }\n```',        "**关键指令**: 你的整个回复**必须**仅仅是JSON对象，不包含任何其他文本。",
    ])

    return "\n".join(prompt_lines)