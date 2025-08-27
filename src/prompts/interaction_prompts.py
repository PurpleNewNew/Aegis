import json
from typing import List, Dict, Any, Optional

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
                    prompt_lines.append(f"- **{tool_name}**: 发现 {len(findings)} 个问题")
                    for finding in findings[:2]: # Limit to 2 for brevity
                        prompt_lines.append(f"  - {str(finding)[:200]}...")
        else:
            prompt_lines.append("无SAST发现")

    if reasoning_level == 'high':
        prompt_lines.append("\n**深度动态分析情报**: (这是我们通过模拟交互、注入探针等方式获得的、最有价值的证据)")
        has_dynamic_findings = False

        js_crypto_analysis = analysis_results.get('js_crypto_analysis')
        if js_crypto_analysis and js_crypto_analysis.get('findings'):
            has_dynamic_findings = True
            prompt_lines.append(f"- **JS/加密分析**: 发现 {len(js_crypto_analysis['findings'])} 个潜在问题")
            for finding in js_crypto_analysis['findings'][:2]:
                prompt_lines.append(f"  - {finding.get('description')}")

        network_analysis = analysis_results.get('network_packet_analysis')
        if network_analysis and network_analysis.get('requests'):
            has_dynamic_findings = True
            prompt_lines.append(f"- **网络数据包分析**: 捕获到 {len(network_analysis['requests'])} 个相关请求")
            if network_analysis.get('security_findings'):
                prompt_lines.append("  - **初步发现**: ")
                for finding in network_analysis['security_findings']:
                    prompt_lines.append(f"    - {finding.get('description')}")

        shadow_analysis = analysis_results.get('shadow_browser_test_results')
        if shadow_analysis and shadow_analysis.get('security_findings'):
            has_dynamic_findings = True
            prompt_lines.append(f"- **影子浏览器主动测试**: 发现 {len(shadow_analysis['security_findings'])} 个潜在问题")
            for finding in shadow_analysis['security_findings']:
                prompt_lines.append(f"  - {finding.get('description')}")

        iast_findings = analysis_results.get('iast_findings', [])
        if iast_findings:
            has_dynamic_findings = True
            prompt_lines.append("- **IAST运行时警报**: (捕获到高风险JS调用)")
            for finding in iast_findings[:2]:
                if finding.get('type') == 'cdp_event':
                    prompt_lines.append(f"  - **[CDP]** 在`{finding.get('trigger')}`事件中，函数`{finding.get('function_name')}`被调用。捕获变量: {json.dumps(finding.get('variables', {}))}")
                elif finding.get('type') == 'iast_event':
                    prompt_lines.append(f"  - **[Hook]** 危险函数`{finding.get('sink')}`被调用，传入值: {str(finding.get('value'))[:100]}...")

        if not has_dynamic_findings:
            prompt_lines.append("无动态分析发现。")

    prompt_lines.extend([
        "",
        "**分析要求**:",
        "1. 综合以上所有信息（特别是深度动态分析情报），分析此交互点是否存在特定的安全风险。",
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
