import json
import re
from typing import List, Dict, Any

def get_js_re_prompt(code_snippet: str, variables: Dict[str, Any], url: str, network_data: List[Dict] = None) -> str:
    """
    构建一个专门用于JS逆向工程分析的提示词。
    """

    variable_list = []
    for name, value in variables.items():
        variable_list.append(f"- `{name}`: `{value}`")
    variables_str = "\n".join(variable_list) if variable_list else "无"

    network_info = ""
    if network_data:
        # 分析网络数据，提取关键请求
        key_requests = []
        for req in network_data:
            if req.get('type') == 'request':
                req_url = req.get('url', '')
                # 检查是否可能是获取密钥的请求
                if 'key' in req_url.lower() or 'token' in req_url.lower() or 'api' in req_url.lower():
                    key_requests.append({
                        'url': req_url,
                        'method': req.get('method', ''),
                        'headers': req.get('headers', {}),
                        'post_data': req.get('post_data')
                    })
        
        if key_requests:
            network_info = "\n**相关的网络请求**\n"
            for i, req in enumerate(key_requests[:3]):  # 只显示前3个相关请求
                network_info += f"\n**请求 {i+1}**:\n"
                network_info += f"- URL: {req['url']}\n"
                network_info += f"- 方法: {req['method']}\n"
                if req.get('post_data'):
                    network_info += f"- POST数据: {req['post_data']}\n"

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
        network_info,
        "",
        "**你的任务**",
        "1. **识别加密/签名算法**：分析代码，判断它使用了哪种或哪几种算法（例如：AES, DES, RSA, MD5, SHA, HMAC, SM2, SM4等）。",
        "2. **定位关键信息**：从代码和变量中，找出加密/签名所使用的密钥（Key）、初始化向量（IV）、盐（Salt）、公钥、私钥或其他重要常量。",
        "3. **分析密钥管理方式**：判断密钥是固定的、从服务器获取的、还是通过某种规律生成的。",
        "4. **识别安全机制**：检查是否存在防重放攻击、时间戳、随机数等安全机制。",
        "5. **解释完整流程**：用清晰的语言，分步描述整个加密/签名过程是如何进行的，包括数据预处理、加密/签名、后处理等步骤。",
        "6. **总结核心发现**：将你的核心发现以JSON格式进行总结。",
        "",
        "**输出要求**",
        "- 先进行详细的文字分析（识别、定位、解释）。",
        "- 在分析的最后，附上一个总结性的JSON对象。",
        "- JSON对象必须包含以下键：",
        "  - `algorithms`: 一个数组，包含所有识别出的算法，如['AES','RSA']",
        "  - `key_management`: 描述密钥管理方式，可选值：'fixed'(固定), 'server_fetched'(服务端获取), 'generated'(规律生成), 'unknown'(未知)",
        "  - `security_mechanisms`: 一个数组，包含识别出的安全机制，如['anti_replay', 'timestamp', 'nonce']",
        "  - `key_source`: 密钥来源描述，如'从变量key中获取'、'通过API /api/key 获取'等",
        "  - `process_summary`: 字符串，完整描述加密/签名流程",
        "  - `vulnerabilities`: 一个数组，包含可能存在的安全弱点，如['fixed_key', 'predictable_iv']",
        "",
        "**常见场景示例**",
        "1. **AES固定密钥**: 密钥在JS代码中硬编码或在变量中直接可见",
        "2. **AES服务端获取密钥**: 通过AJAX请求从服务器获取密钥，然后进行AES加密",
        "3. **RSA加密**: 使用服务器公钥进行RSA加密",
        "4. **AES+RSA混合加密**: 先用AES加密数据，再用RSA加密AES密钥",
        "5. **DES规律密钥**: 密钥通过某种算法或规律生成",
        "6. **明文加签**: 对明文数据进行签名",
        "7. **加签key在服务器端**: 通过服务器接口获取签名用的密钥或直接请求服务器签名",
        "8. **禁止重放**: 使用时间戳、随机数或序列号防止重放攻击",
        "",
        "**特别注意**",
        "- 如果发现代码中有发送网络请求获取密钥的逻辑，请详细分析该过程",
        "- 对于服务端获取密钥的场景，需要描述完整的密钥获取和使用流程",
        "- 分析密钥是否在使用后被正确清理",
        "",
        "**JSON输出示例**",
        "```json",
        json.dumps({
            "algorithms": ["AES", "RSA"],
            "key_management": "server_fetched",
            "security_mechanisms": ["anti_replay", "timestamp"],
            "key_source": "通过API /api/getKey 获取RSA公钥，用于加密AES密钥",
            "process_summary": "函数首先向/api/getKey发送请求获取RSA公钥，然后生成随机的AES密钥和IV，使用AES对明文数据进行加密，再使用RSA公钥加密AES密钥和IV，最后将加密后的数据和加密后的密钥一起发送到服务器。",
            "vulnerabilities": ["none"]
        }, indent=2, ensure_ascii=False),
        "```"
    ]

    return "\n".join(prompt_lines)