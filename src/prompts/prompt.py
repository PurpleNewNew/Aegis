import json
from typing import List, Dict, Any

def get_js_re_prompt(code_snippet: str, variables: Dict[str, Any], url: str) -> str:
    """
    构建一个专门用于JS逆向工程分析的提示词。
    """

    variable_list = []
    for name, value in variables.items():
        variable_list.append(f"- `{name}`: `{value}`")
    variables_str = "\n".join(variable_list) if variable_list else "无"

    prompt_lines = [
        "你是一名顶级的JavaScript逆向工程专家，尤其擅长分析和破解前端加密逻辑。",
        "",
        "**任务背景**",
        f"- 我正在对网站 `{url}` 进行安全分析。",
        "- 我通过CDP调试器，在一个关键的交互事件（如click）触发时，捕获到了以下JavaScript代码片段和当时的变量状态。",
        "- 我怀疑这段代码执行了关键的加密操作。",
        "",
        "**捕获到的代码片段**",
        "```javascript",
        code_snippet,
        "```",
        "",
        "**捕获到的相关变量**",
        variables_str,
        "",
        "**你的任务**",
        "1. **识别加密算法**：分析代码，判断它使用了哪种或哪几种加密算法（例如：AES, DES, RSA, MD5, SHA等）。",
        "2. **定位关键信息**：从代码和变量中，找出加密所使用的密钥（Key）、初始化向量（IV）、盐（Salt）、公钥或其他重要常量。",
        "3. **解释加密流程**：用清晰的语言，分步描述整个加密过程是如何进行的。",
        "4. **总结核心发现**：将你的核心发现以JSON格式进行总结。",
        "",
        "**输出要求**",
        "- 先进行详细的文字分析（识别、定位、解释）。",
        "- 在分析的最后，附上一个总结性的JSON对象。",
        "- JSON对象必须包含 `algorithm`, `key`, `iv`, `process_summary` 这几个键。如果某个值找不到，请用 `null` 表示。",
        "",
        "**JSON输出示例**",
        "```json",
        json.dumps({
            "algorithm": "AES-128-CBC",
            "key": "从变量 a 中找到的密钥...",
            "iv": "一个16字节的固定值...",
            "process_summary": "函数首先用key和iv初始化AES实例，然后对输入数据进行padding，最后执行加密并返回Base64编码结果。"
        }, indent=2, ensure_ascii=False),
        "```"
    ]

    return "\n".join(prompt_lines)
