"""
集中化模块，用于存储和生成面向LLM的高度优化的提示词。
包含两阶段分析所需的提示：JS摘要 和 关联分析。
"""
import json
from datetime import datetime

def get_js_summary_prompt(js_url: str, js_content: str) -> str:
    """
    构建一个提示词，用于让LLM总结一个JS文件的功能。
    """
    # 截断以防止上下文溢出，因为摘要任务相对简单
    max_len = 15000
    if len(js_content) > max_len:
        js_content = js_content[:max_len] + "\n... (代码过长已被截断) ..."

    prompt_lines = [
        "你是一名精通JavaScript的资深软件工程师。",
        "",
        "**任务**:",
        f"请简要总结以下从URL `{js_url}` 获取的JavaScript文件的核心功能。你的总结应当清晰、简洁，并突出任何与安全相关的方面。",
        "",
        "**分析要点**:",
        "1.  **核心功能**: 这个JS文件的主要目的是什么？（例如：处理用户认证、UI交互、数据加密、广告追踪等）",
        "2.  **关键函数/变量**: 列出1-3个最关键的函数或变量名，并简要说明其作用。",
        "3.  **安全相关元素**: 是否发现了任何看起来像API密钥、认证令牌、加密函数调用、或API端点的东西？只需列出，无需深入分析。",
        "",
        "**JavaScript 代码内容**:",
        f"```javascript\n{js_content}\n```",
        "",
        "**关键指令**: 你的回复必须是纯文本，直接回答上述三个问题即可，不需要任何额外的寒暄或解释。"
    ]
    return "\n".join(prompt_lines)

def get_correlation_prompt(context_package: dict, memories: dict) -> str:
    """
    构建一个“大师级”的详细提示词，用于对一个包含JS摘要的上下文进行整体性关联分析。
    """
    initiator_url = context_package.get('initiator_url')
    requests = context_package.get('requests', [])
    # 注意：现在接收的是带有摘要的JS文件对象
    summarized_js_files = context_package.get('summarized_js', [])

    # --- 1. 构建事件叙事 ---
    # 注意：这里我们只有请求事件，因为JS文件已被预处理
    event_narrative_lines = ["\n**此页面生命周期中发生的网络请求（按大致顺序）**:"]
    if not requests:
        event_narrative_lines.append("未捕获到任何网络请求。" )
    else:
        # 按时间戳对请求排序
        sorted_requests = sorted(requests, key=lambda x: x.get('timestamp', 0))
        for i, req in enumerate(sorted_requests):
            ts = datetime.fromtimestamp(req.get('timestamp', 0)).strftime('%H:%M:%S')
            event_narrative_lines.append(f"{i+1}. `[{ts}]` **发出网络请求**: `{req.get('method')}` `{req.get('url')}`")
    event_narrative = "\n".join(event_narrative_lines)

    # --- 2. 构建JS代码摘要部分 ---
    js_summary_section_lines = ["\n**此页面加载的JS文件的AI摘要（用于关联分析）**:"]
    if not summarized_js_files:
        js_summary_section_lines.append("无相关的JS文件摘要。" )
    else:
        for i, js_file in enumerate(summarized_js_files):
            js_url = js_file.get('url')
            summary = js_file.get('summary', '摘要生成失败。')
            js_summary_section_lines.append(f"--- JS文件摘要 {i+1}: `{js_url}` ---")
            js_summary_section_lines.append(summary)
    js_summary_section = "\n".join(js_summary_section_lines)

    # --- 3. 构建历史记忆部分 ---
    memory_section_lines = ["\n**历史分析（记忆）**:"]
    if memories and memories.get('documents') and memories['documents'][0]:
        memory_section_lines.append("以下是从该URL或相似端点过往的分析中提取的记忆，请将其作为重要参考：")
        for mem in memories['documents'][0]:
            memory_section_lines.append(f"- {mem}")
    else:
        memory_section_lines.append("- 无相关历史记忆。" )
    memory_section = "\n".join(memory_section_lines)

    # --- 4. 构建安全的JSON范例 ---
    example_finding = json.dumps([
        {
            "vulnerability": "不安全的密码加密传输",
            "confidence": "High",
            "severity": "High",
            "reasoning": "JS文件摘要中提到 `auth.js` 使用 `encryptPassword` 函数处理密码，但摘要显示该函数只是对密码进行了Base64编码。在网络请求中，发往 `/api/login` 的POST请求的body中，`password` 字段的值确实是一个Base64编码的字符串。Base64是编码而非加密，密码在传输过程中相当于明文，这是严重的安全漏洞。",
            "suggestion": "前端应使用非对称加密（如RSA）的用户公钥对密码进行加密，或在安全的HTTPS连接上直接传输密码原文，由后端进行哈希处理。绝不能使用Base64等编码方式伪装成加密。"
        }
    ], indent=2, ensure_ascii=False)

    # --- 5. 组装最终的Prompt ---
    prompt_lines = [
        f"你是一名顶级的、全栈的渗透测试专家，你的任务是像一个真实的人类黑客一样思考，对一个Web页面的**完整用户会话**进行全面的、上下文感知的安全审计。",
        "",
        "**核心任务**:",
        "请**关联分析**以下所有信息：网络请求、相关的JS代码摘要、以及历史记忆，以发现单个事件无法暴露的深层次漏洞。",
        "",
        f"**分析场景**: 正在审计的页面是 `{initiator_url}`",
        event_narrative,
        js_summary_section,
        memory_section,
        "",
        "**关键关联分析指令**:",
        "1.  **数据流追踪**: 结合JS摘要中提到的功能（如加密、参数构造）和网络请求的实际参数，判断是否存在数据在传输前处理不当（如加密薄弱、敏感信息拼接）的情况？",
        "2.  **逻辑漏洞分析**: 结合JS摘要中提到的业务逻辑和实际发出的网络请求序列，判断是否存在可以被利用的流程缺陷？",
        "",
        "**输出要求**:",
        "你的回答**必须**是一个JSON对象数组。每个对象代表一个发现。如果未发现任何漏洞，则返回一个空数组 `[]`。",
        "",
        "**这是一个完美的输出范例**:",
        f"```json\n{example_finding}\n```",
        "",
        "**关键指令**: 你的整个回复**必须**仅仅是一个JSON数组，不包含任何介绍、解释、总结或其他任何非JSON文本。请直接以 `[` 开始，并以 `]` 结束。"
    ]
    
    return "\n".join(prompt_lines)