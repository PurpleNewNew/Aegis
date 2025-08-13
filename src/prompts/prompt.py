
"""
集中化模块，用于存储和生成面向LLM的高度优化的提示词。
"""
import json
from datetime import datetime

# --- 智能预处理辅助函数 ---

def is_likely_library(url: str) -> bool:
    """通过URL启发式地判断一个JS文件是否为第三方库。"""
    url_lower = url.lower()
    library_indicators = [
        '.min.js', 'jquery', 'bootstrap', 'angular', 'react', 
        'vue.js', 'chart.js', 'd3.js', 'moment.js', 'lodash', 
        'crypto-js', 'jsencrypt', 'forge.min', 'cdn.jsdelivr.net', 
        'cdnjs.cloudflare.com', 'unpkg.com', 'googleapis.com'
    ]
    return any(indicator in url_lower for indicator in library_indicators)

def get_holistic_analysis_prompt(context_package: dict, memories: dict) -> str:
    """
    构建一个“大师级”的详细提示词，用于对一个完整的页面上下文进行整体性关联分析，
    并要求以JSON格式输出。
    """
    initiator_url = context_package.get('initiator_url')
    requests = context_package.get('requests', [])
    js_files = context_package.get('js_files', [])

    # --- 1. 构建事件叙事 ---
    all_events = sorted(requests + js_files, key=lambda x: x.get('timestamp', 0))
    event_narrative_lines = ["\n**事件时间线（按发生顺序）**:" ]
    if not all_events:
        event_narrative_lines.append("未捕获到任何事件。")
    else:
        for i, event in enumerate(all_events):
            ts = datetime.fromtimestamp(event.get('timestamp', 0)).strftime('%H:%M:%S')
            if event.get('event_type') == 'javascript_file':
                event_narrative_lines.append(f"{i+1}. `[{ts}]` **加载JS文件**: `{event.get('url')}`")
            elif event.get('event_type') == 'request':
                event_narrative_lines.append(f"{i+1}. `[{ts}]` **发出网络请求**: `{event.get('method')}` `{event.get('url')}`")
    event_narrative = "\n".join(event_narrative_lines)

    # --- 2. 智能分离和处理JS文件 ---
    app_js_files = [f for f in js_files if not is_likely_library(f.get('url', ''))]
    lib_js_files = [f for f in js_files if is_likely_library(f.get('url', ''))]

    # 2a. 构建第三方库依赖清单
    library_section_lines = ["\n**第三方库依赖清单**:" ]
    if not lib_js_files:
        library_section_lines.append("- 未发现已知的第三方库依赖。")
    else:
        for lib in lib_js_files:
            library_section_lines.append(f"- `{lib.get('url')}`")
    library_section = "\n".join(library_section_lines)

    # 2b. 构建应用自身的JS代码审查部分
    js_code_section_lines = ["\n**捕获到的应用自有JavaScript文件内容（用于代码审计）**:"]
    if not app_js_files:
        js_code_section_lines.append("未捕获到应用自身的JS文件。")
    else:
        for i, js_file in enumerate(app_js_files):
            js_url = js_file.get('url')
            js_content = js_file.get('content', '')
            max_len = 12000
            if len(js_content) > max_len:
                js_content = js_content[:max_len] + "\n... (代码过长已被截断) ..."
            js_code_section_lines.append(f"--- 应用JS文件 {i+1}: `{js_url}` ---")
            js_code_section_lines.append(f"```javascript\n{js_content}\n```")
    js_code_section = "\n".join(js_code_section_lines)

    # --- 3. 构建历史记忆部分 ---
    memory_section_lines = ["\n**历史分析（记忆）**:" ]
    if memories and memories.get('documents') and memories['documents'][0]:
        memory_section_lines.append("以下是从该URL或相似端点过往的分析中提取的记忆，请将其作为重要参考：")
        for mem in memories['documents'][0]:
            memory_section_lines.append(f"- {mem}")
    else:
        memory_section_lines.append("- 无相关历史记忆。")
    memory_section = "\n".join(memory_section_lines)

    # --- 4. 构建安全的JSON范例 ---
    example_finding = json.dumps([
        {
            "vulnerability": "硬编码在JS中的密钥被用于API请求",
            "confidence": "High",
            "severity": "Critical",
            "reasoning": "在`app.js`中发现硬编码的API密钥`const API_KEY = \"sk_...\"`。此密钥随后被用于构造发往`api.example.com`的请求头。",
            "suggestion": "立即废止此密钥，并从前端代码中移除。通过后端代理调用需要认证的API。"
        },
        {
            "vulnerability": "依赖存在已知漏洞的库 (CVE-2018-9206)",
            "confidence": "High",
            "severity": "Medium",
            "reasoning": "依赖清单中包含了`jquery-3.2.1.min.js`。该版本的jQuery存在一个已知的跨站脚本（XSS）漏洞(CVE-2018-9206)。",
            "suggestion": "将jQuery库升级到3.4.0或更高版本以修复此漏洞。"
        }
    ], indent=2, ensure_ascii=False)

    # --- 5. 组装最终的Prompt ---
    prompt_lines = [
        f"你是一名顶级的、全栈的渗透测试专家，你的任务是像一个真实的人类黑客一样思考，对一个Web页面的**完整用户会话**进行全面的、上下文感知的安全审计。",
        "",
        "**核心任务**:",
        "请**关联分析**以下所有信息，发现单个事件无法暴露的深层次漏洞。你必须**连接这些信息点**。",
        "",
        f"**分析场景**: 正在审计的页面是 `{initiator_url}`",
        event_narrative,
        library_section, # 新增
        js_code_section,
        memory_section,
        "",
        "**关键关联分析指令 (请一步步思考并回答)**:",
        "1.  **依赖漏洞分析**: 检查“第三方库依赖清单”，列出的库是否存在任何已知的、公开的漏洞（CVEs）?",
        "2.  **数据流追踪**: 仔细检查“应用自有JS文件内容”，寻找其中定义的变量、函数或加密逻辑。然后，在“事件时间线”中，判断这些JS定义的元素（如API密钥、加密后的密码）是否出现在了后续发出的网络请求中?",
        "3.  **因果链/逻辑漏洞分析**: 整个事件序列是否构成了一个完整的用户操作（如登录、搜索）？这个流程是否存在逻辑缺陷（如可以绕过步骤）？后续请求是否不安全地依赖于之前请求的返回数据？",
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
