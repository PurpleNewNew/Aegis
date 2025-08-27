import json
import re
from typing import List, Dict, Any

def get_js_re_prompt(code_snippet: str, variables: Dict[str, Any], url: str, 
                    network_data: List[Dict] = None, js_hook_events: List[Dict] = None, 
                    analysis_context: Dict = None, call_stack: List[str] = None) -> str:
    """
    构建一个专门用于JS逆向工程分析的提示词。
    
    Args:
        code_snippet: JavaScript代码片段
        variables: 变量字典
        url: 目标URL
        network_data: 网络数据列表
        js_hook_events: JS钩子事件列表
        analysis_context: 分析上下文
        call_stack: 调用栈
    """

    # 格式化变量
    variable_list = []
    for name, value in variables.items():
        variable_list.append(f"- `{name}`: `{value}`")
    variables_str = "\n".join(variable_list) if variable_list else "无"

    # 格式化调用栈
    call_stack_info = ""
    if call_stack:
        # 反转调用栈，使其更符合人类阅读直觉
        reversed_stack = " -> ".join(reversed(call_stack))
        call_stack_info = f"\n**函数调用路径**\n`{reversed_stack}`\n"

    # 分析网络请求数据
    network_info = ""
    if network_data:
        # 按时间戳排序请求
        sorted_requests = sorted(network_data, key=lambda x: x.get('timestamp', 0))
        
        # 识别可能的密钥请求
        key_requests = []
        for req in sorted_requests:
            if req.get('type') == 'request':
                req_url = req.get('url', '')
                # 检查是否可能是获取密钥的请求
                if 'key' in req_url.lower() or 'token' in req_url.lower() or 'api' in req_url.lower():
                    key_requests.append(req)
        
        if key_requests:
            network_info = "\n**相关的网络请求**\n"
            for i, req in enumerate(key_requests[:3]):  # 只显示前3个相关请求
                network_info += f"\n**请求 {i+1}**:\n"
                network_info += f"- URL: {req['url']}\n"
                network_info += f"- 方法: {req['method']}\n"
                if req.get('post_data'):
                    post_data_preview = str(req['post_data'])[:200] + ('...' if len(str(req['post_data'])) > 200 else '')
                    network_info += f"- POST数据: {post_data_preview}\n"
                
                # 检查是否有对应的响应
                if req.get('response'):
                    network_info += f"- 响应状态: {req['response']['status']}\n"
                    if req['response']['body']:
                        # 限制响应体显示长度
                        body_preview = req['response']['body'][:200] + ('...' if len(req['response']['body']) > 200 else '')
                        network_info += f"- 响应体预览: {body_preview}\n"
        
        # 分析请求之间的关系
        if len(sorted_requests) > 1:
            network_info += "\n**请求关系分析**\n"
            # 查找可能的密钥请求和后续使用密钥的请求
            key_request_indices = []
            for i, req in enumerate(sorted_requests):
                if req.get('type') == 'request' and ('key' in req.get('url', '').lower() or 'token' in req.get('url', '').lower()):
                    key_request_indices.append(i)
            
            if key_request_indices:
                for i in key_request_indices:
                    if i + 1 < len(sorted_requests):
                        network_info += f"- 请求 {i+1} (可能包含密钥) 之后紧跟着请求 {i+2}\n"
            
            # 检查是否有请求在获取密钥后立即发送加密数据
            for i in key_request_indices:
                if i + 1 < len(sorted_requests):
                    next_req = sorted_requests[i+1]
                    if next_req.get('type') == 'request' and ('encrypt' in next_req.get('url', '').lower() or 'data' in next_req.get('url', '').lower()):
                        network_info += f"- 请求 {i+2} 可能使用了请求 {i+1} 获取的密钥进行加密操作\n"
    
    # 分析JS钩子事件
    js_hook_info = ""
    if js_hook_events:
        js_hook_info = "\n**JS钩子事件**\n"
        
        # 按时间戳排序事件
        sorted_events = sorted(js_hook_events, key=lambda x: x.get('timestamp', 0))
        
        # 识别加密相关事件
        crypto_events = []
        for event in sorted_events[:10]:  # 只显示前10个事件
            event_type = event.get('type', '')
            function_name = event.get('functionName', '')
            
            # 检查是否是加密相关事件
            if any(keyword in function_name.lower() for keyword in ['encrypt', 'decrypt', 'hash', 'sign', 'aes', 'rsa', 'md5', 'sha', 'cipher', 'hmac', 'pbkdf2', 'scrypt', 'bcrypt']):
                crypto_events.append(event)
            elif event_type in ['function_call', 'function_return'] and any(keyword in function_name.lower() for keyword in ['crypto', 'key', 'token', 'encode', 'decode', 'obfuscate', 'obfuscation']):
                crypto_events.append(event)
        
        if crypto_events:
            js_hook_info += "\n**加密相关函数调用**:\n"
            for i, event in enumerate(crypto_events[:5]):  # 只显示前5个加密相关事件
                js_hook_info += f"\n**事件 {i+1}**:\n"
                js_hook_info += f"- 函数名: {event.get('functionName', 'unknown')}\n"
                js_hook_info += f"- 事件类型: {event.get('type', 'unknown')}\n"
                if event.get('args'):
                    args_preview = str(event['args'])[:150] + ('...' if len(str(event['args'])) > 150 else '')
                    js_hook_info += f"- 参数: {args_preview}\n"
                if event.get('returnValue'):
                    return_preview = str(event['returnValue'])[:150] + ('...' if len(str(event['returnValue'])) > 150 else '')
                    js_hook_info += f"- 返回值: {return_preview}\n"
        
        # 分析事件序列
        if len(sorted_events) > 1:
            js_hook_info += "\n**事件序列分析**:\n"
            # 查找可能的密钥获取和加密序列
            for i, event in enumerate(sorted_events):
                if i + 1 < len(sorted_events):
                    current_func = event.get('functionName', '').lower()
                    next_func = sorted_events[i+1].get('functionName', '').lower()
                    
                    # 检查是否是密钥获取后立即加密的模式
                    if ('key' in current_func or 'token' in current_func) and ('encrypt' in next_func or 'sign' in next_func):
                        js_hook_info += f"- {event.get('functionName')} -> {sorted_events[i+1].get('functionName')} (可能的密钥获取+加密序列)\n"
    
    # 添加分析上下文信息
    context_info = ""
    if analysis_context:
        context_info = "\n**分析上下文**\n"
        
        # 添加会话信息
        if analysis_context.get('session_info'):
            session_info = analysis_context['session_info']
            context_info += f"\n- 会话ID: {session_info.get('session_id', 'unknown')}\n"
            context_info += f"- 会话持续时间: {session_info.get('duration', 'unknown')}\n"
        
        # 添加数据统计
        if analysis_context.get('data_stats'):
            stats = analysis_context['data_stats']
            context_info += "\n- 数据统计:\n"
            for data_type, count in stats.items():
                context_info += f"  - {data_type}: {count} 条\n"
        
        # 添加时间线摘要
        if analysis_context.get('timeline_summary'):
            timeline = analysis_context['timeline_summary']
            context_info += "\n- 时间线摘要:\n"
            for event in timeline[:3]:  # 只显示前3个事件
                context_info += f"  - {event.get('type', 'unknown')} @ {event.get('timestamp', 'unknown')}\n"

    # 构建完整提示词
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
        call_stack_info,
        network_info,
        js_hook_info,
        context_info,
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
        "**分析建议**",
        "- 重点关注代码中的加密/解密函数调用",
        "- 注意变量中可能包含的密钥、IV等敏感信息",
        "- 结合网络请求分析密钥获取流程",
        "- 考虑调用栈上下文，理解函数调用关系",
        "- 注意JS钩子捕获的加密相关函数调用",
        "",
        "现在，请开始你的分析："
    ]
    
    return "\n".join(prompt_lines)