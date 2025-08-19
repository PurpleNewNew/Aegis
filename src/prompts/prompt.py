import json
from typing import List, Dict, Any

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

def get_interaction_analysis_prompt(interaction_type: str, snapshot: Dict[str, Any], analysis_results: Dict[str, Any], goal: str) -> str:
    """
    构建用于交互分析的提示词，专门分析用户交互点的安全风险。
    """
    prompt_lines = [
        "你是一名专业的Web安全分析师，专门分析用户交互点的安全风险。",
        "",
        f"**交互类型**: {interaction_type}",
        f"**分析目标**: {goal}",
        "",
        "**交互快照信息**:",
        f"- URL: {snapshot.get('url', 'N/A')}",
        f"- 页面标题: {snapshot.get('title', 'N/A')}",
        f"- 交互时间戳: {snapshot.get('timestamp', 'N/A')}",
        "",
        "**目标元素信息**:",
        f"```json",
        f"{json.dumps(snapshot.get('target_element', {}), indent=2, ensure_ascii=False)}",
        f"```",
        "",
        "**SAST扫描结果**:",
    ]
    
    # 添加SAST结果
    sast_results = snapshot.get('sast_results', {})
    if sast_results and any(findings for findings in sast_results.values()):
        for tool_name, findings in sast_results.items():
            if findings:
                prompt_lines.append(f"- **{tool_name}**: 发现 {len(findings)} 个问题")
                for finding in findings[:3]:  # 只显示前3个
                    prompt_lines.append(f"  - {str(finding)}")
                if len(findings) > 3:
                    prompt_lines.append(f"  ... 还有 {len(findings) - 3} 个问题")
    else:
        prompt_lines.append("无SAST发现")

    # 添加深度分析结果
    prompt_lines.append("\n**深度动态分析情报**: (这是我们通过模拟交互、注入探针等方式获得的、最有价值的证据)")
    has_dynamic_findings = False

    # JS断点分析结果
    js_analysis = analysis_results.get('js_breakpoint_analysis')
    if js_analysis:
        prompt_lines.append("- **JS事件处理器分析**:")
        # Show inline handlers
        if js_analysis.get('inline_handlers'):
            has_dynamic_findings = True
            prompt_lines.append("  - **内联处理器 (e.g., onclick)**:")
            for handler in js_analysis.get('inline_handlers', [])[:2]: # Limit to 2
                prompt_lines.append(f"    - **类型**: {handler.get('type')}")
                prompt_lines.append(f"    - **代码**: ```javascript\n{handler.get('handler_code', '')[:500]}\n```") # Limit code length
        # Show dynamically added listeners
        if js_analysis.get('event_listeners'):
            has_dynamic_findings = True
            prompt_lines.append("  - **动态绑定监听器 (addEventListener)**:")
            for listener in js_analysis.get('event_listeners', [])[:2]: # Limit to 2
                prompt_lines.append(f"    - **类型**: {listener.get('type')}")
                prompt_lines.append(f"    - **代码**: ```javascript\n{listener.get('listener_code', '')[:500]}\n```") # Limit code length
        # Show the findings derived from them
        if js_analysis.get('security_findings'):
            has_dynamic_findings = True
            prompt_lines.append("  - **初步发现**: ")
            for finding in js_analysis.get('security_findings', []):
                prompt_lines.append(f"    - {finding.get('description')}")

    # 网络数据包分析结果
    network_analysis = analysis_results.get('network_packet_analysis')
    if network_analysis and network_analysis.get('requests'):
        has_dynamic_findings = True
        prompt_lines.append(f"- **网络数据包分析**: 捕获到 {len(network_analysis['requests'])} 个相关请求")
        for req in network_analysis['requests'][:2]: # Limit to 2
            prompt_lines.append(f"  - **请求**: {req.get('method')} {req.get('url')}")
        if network_analysis.get('security_findings'):
            prompt_lines.append("  - **初步发现**: ")
            for finding in network_analysis['security_findings']:
                prompt_lines.append(f"    - {finding.get('description')}")

    # 影子浏览器测试结果
    shadow_analysis = analysis_results.get('shadow_browser_test_results')
    if shadow_analysis and shadow_analysis.get('security_findings'):
        has_dynamic_findings = True
        prompt_lines.append(f"- **影子浏览器主动测试**: 发现 {len(shadow_analysis['security_findings'])} 个潜在问题")
        for finding in shadow_analysis['security_findings']:
            prompt_lines.append(f"  - {finding.get('description')} (类型: {finding.get('type')})")

    if not has_dynamic_findings:
        prompt_lines.append("无动态分析发现。")

    # 添加表单数据（如果有）
    form_data = snapshot.get('form_data', {})
    if form_data:
        prompt_lines.extend([
            "",
            "**表单数据**:",
            f"```json",
            f"{json.dumps(form_data, indent=2, ensure_ascii=False)}",
            f"```"
        ])
    
    # 添加分析指令
    prompt_lines.extend([
        "",
        "**分析要求**:",
        "1. 综合以上所有信息（特别是深度动态分析情报），分析此交互点是否存在特定的安全风险。",
        "2. 不要提出宽泛、通用的建议，你的分析必须基于上面提供的具体情报。",
        "3. 如果动态分析情报中存在明确的漏洞证据（如XSS、敏感信息泄露），请直接在风险评估中指出。",
        "4. 提供具体的安全建议和修复方案。",
        "",
        "**输出格式**:",
        "请以JSON格式返回分析结果，包含以下字段：",
        "```json",
        "{",
        '  "risk_assessment": "风险等级 (Critical/High/Medium/Low/Informational)",',
        '  "analysis_summary": "(string) 对你发现的具体问题的简要总结。如果没有发现，请说明理由。",',
        '  "security_recommendations": ["具体的建议1", "具体的建议2"],',
        '  "potential_attack_vectors": ["具体的攻击向量1", "具体的攻击向量2"]',
        "}",
        "```",
        "",
        "**重要提醒**:",
        "- 你的回复必须仅仅是JSON对象，不包含任何其他文本",
        "- 不要在JSON外面添加代码块标记",
        "- 基于实际的风险给出客观评估，如果没有明确证据，不要夸大风险。"
    ])
    
    return "\n".join(prompt_lines)


def get_agent_reasoning_prompt(goal: str, history: List[Dict[str, Any]], observation: str, sast_results: Dict[str, List[str]], iast_findings: List[Dict[str, str]], long_term_memories: List[str]) -> str:
    """
    构建一个提示词，用于驱动“AI指挥官”进行思考和决策。
    这个Prompt整合了所有维度的信息。
    """
    tools_description = ""
    for name, details in AVAILABLE_TOOLS.items():
        tools_description += f"- `{name}`: {details['description']}\n"
        if details['args']:
            tools_description += "  参数:\n"
            for arg_name, arg_desc in details['args'].items():
                tools_description += f"    - `{arg_name}`: {arg_desc}\n"

    history_section = ""
    if history:
        history_section += "\n**历史操作与观察**:\n"
        for item in history:
            history_section += f"- **你的上一步决策**: {item['thought']}\n"
            history_section += f"- **你执行的动作**: 调用工具 `{item['tool_call']['name']}`，参数为 `{item['tool_call']['args']}`\n"
            history_section += f"- **你得到的观察结果**: {item['observation']}\n"
    
    sast_section = "\n**自动化静态扫描(SAST)初步线索**:\n"
    has_sast_findings = False
    if sast_results:
        for tool_name, findings in sast_results.items():
            if findings:
                has_sast_findings = True
                sast_section += f"- **`{tool_name}` 发现了 {len(findings)} 个线索**:\n"
                for finding in findings:
                    sast_section += f"  - {str(finding)}\n"
    if not has_sast_findings:
        sast_section += "无任何发现。\n"

    iast_section = "\n**交互式运行时(IAST)警报**:\n"
    if iast_findings:
        iast_section += "**警告**: 在你上一步的操作中，我们的探针捕获到了以下高风险的运行时事件，这很可能是漏洞的直接证据！\n"
        for finding in iast_findings:
            if finding.get('sink') == 'CDPDebugger':
                iast_section += f"- **[CDP调试器]** 捕获到原始事件: `{finding.get('value')}`\n"
            else:
                iast_section += f"- **[JS Hook]** 危险函数 `{finding.get('sink')}` 被调用，传入的值(部分): `{finding.get('value')}`\n"
    else:
        iast_section += "无任何运行时警报。\n"

    memory_section = "\n**长期记忆（来自相似架构网站的过往经验）**:\n"
    if long_term_memories:
        for mem in long_term_memories:
            memory_section += f"- {mem}\n"
    else:
        memory_section += "无相关历史经验可供参考。\n"

    observation_block = f"```\n{observation}\n```"

    prompt_lines = [
        "你是一名顶级的安全测试总指挥，负责领导一次对Web应用的渗透测试。",
        "你的手下有自动化脚本（SAST）和运行时探针（IAST），它们会为你提供关键线索。",
        "你的核心价值在于，结合这些静态和动态的\"铁证\"，进行高级的逻辑推理，并决策执行动态交互来最终确认和利用漏洞。",
        "",
        "**重点关注的安全问题**:",
        "- 🔐 **加密弱点**: 固定密钥、弱加密算法、密钥泄露、不安全的加密实现",
        "- 📝 **身份验证**: 弱密码、默认凭证、认证绕过",
        "- 🕳️ **会话管理**: 会话固定、重放攻击、CSRF",
        "- 🖉 **注入攻击**: SQL注入、XSS、命令注入",
        "- 📂 **信息泄露**: 敏感数据暴露、错误信息泄露、目录遍历",
        "",
        f"**总任务目标**: {goal}",
        "",
        "**可用交互工具清单 (你的\"双手\")**:",
        tools_description,
        "",
        history_section,
        "",
        sast_section,
        iast_section,
        memory_section,
        "",
        "**当前的动态观察结果 (你\"眼睛\"看到的)**:",
        observation_block,
        "",
        "**你的任务**:",
        "1.  **评估**: 基于你的总任务目标和历史记录，判断对当前页面功能点的测试是否已经充分？是否已经没有更多有价值的交互可以尝试了？",
        "2.  **思考**: 如果测试不充分，请优先分析IAST和SAST的线索，用一句话总结你下一步的测试思路。如果是，请简单总结你的发现。",
        "3.  **决策**: ",
        "    - **如果**你确信发现了一个漏洞，你的下一步行动**必须**是调用 `report_finding` 工具来记录它。",
        "    - **如果**你认为还需要更多信息，或者需要验证一个线索，请从工具清单中选择一个交互工具（如`click_element`, `input_text`）来执行。",
        "    - **如果**你认为对当前页面的所有功能点和线索的测试都已充分完成，请调用 `finish_investigation` 工具。",
        "",
        "**输出要求**:",
        "你的回答**必须**是一个JSON对象，且只包含 `thought` 和 `tool_call` 两个键。",
        "",
        "**JSON输出示例**:",
        "```json",
        '{ "thought": "我应该点击注册按钮来探索注册功能", "tool_call": { "name": "click_element", "args": { "selector": "[data-aegis-id=\\"aegis-el-7\\"]" } } }',
        "```",
        "",
        "或者：",
        "```json",
        '{ "thought": "当前页面测试充分，没有发现明显的安全问题", "tool_call": { "name": "finish_investigation", "args": { "summary": "已完成对登录页面的全面测试，未发现SQL注入或XSS漏洞" } } }',
        "```",
        "",
        "**重要提醒**:",
        "- 每个工具都有特定的参数要求，请确保提供所有必需的参数",
        "- click_element 需要 selector 参数（从 interactive_elements 中选择）",
        "- input_text 需要 selector 和 text 两个参数",
        "- 如果没有args，使用空对象 {}",
        "",
        "**关键指令**: 你的整个回复**必须**仅仅是JSON对象，不包含任何其他文本。不要在JSON外面添加代码块标记。"
    ]

    return "\n".join(prompt_lines)
