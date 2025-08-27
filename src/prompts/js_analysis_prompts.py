import json
from typing import List, Dict, Any, Optional

def get_js_analysis_prompt(
    code_context: str, 
    variables: Dict[str, Any], 
    url: str,
    function_name: str = "",
    call_stack: List[str] = None,
    network_events: List[Dict] = None,
    reasoning_level: str = 'medium'
) -> str:
    """
    构建简化的JS逆向分析提示词，专门用于分析加密函数和安全相关代码
    """
    
    # 格式化变量信息
    variables_str = ""
    if variables:
        variables_str = "\n**关键变量**:\n"
        for name, value in list(variables.items())[:10]:  # 限制变量数量
            if isinstance(value, str) and len(value) > 100:
                value = value[:100] + "..."
            variables_str += f"- {name}: {value}\n"
    
    # 格式化调用栈
    call_stack_str = ""
    if call_stack and len(call_stack) > 0:
        call_stack_str = f"\n**调用栈**: {' -> '.join(call_stack[-3:])}\n"  # 只显示最近3层
    
    # 格式化网络事件
    network_str = ""
    if network_events:
        crypto_requests = [e for e in network_events if 'encrypt' in e.get('url', '').lower() or 'key' in e.get('url', '').lower()]
        if crypto_requests:
            network_str = "\n**相关网络请求**:\n"
            for req in crypto_requests[:3]:  # 只显示前3个
                network_str += f"- {req.get('method', 'GET')} {req.get('url', '')}\n"
    
    # 根据推理级别调整详细程度
    detail_level = "简要" if reasoning_level == 'low' else "详细"
    
    prompt = f"""你是一名JavaScript安全分析专家，正在分析一个可能包含加密或安全机制的函数。

**目标URL**: {url}
**函数名**: {function_name or "<anonymous>"}
**分析级别**: {detail_level}

**代码片段**:
```javascript
{code_context[:800]}  # 限制代码长度
```
{variables_str}{call_stack_str}{network_str}
请分析这段代码，重点关注：

1. **加密算法识别**: 识别使用的加密/编码算法（如AES、RSA、Base64、自定义加密等）
2. **安全机制**: 识别密码学操作、密钥处理、签名验证等
3. **潜在漏洞**: 检查硬编码密钥、弱加密、不安全的随机数生成等
4. **数据流**: 追踪敏感数据的处理流程

以JSON格式输出你的分析结果：
{{
    "algorithm": "检测到的算法类型",
    "security_mechanism": "发现的安全机制描述",
    "findings": [
        {{
            "type": "加密算法/安全漏洞/数据流",
            "description": "具体发现",
            "severity": "High/Medium/Low",
            "evidence": "代码证据"
        }}
    ],
    "recommendations": ["安全建议"]
}}

如果代码不涉及加密或安全机制，返回 {{"analysis": "无关"}}"""
    
    return prompt

def get_js_crypto_detection_prompt(page_source: str, url: str, reasoning_level: str = 'medium') -> str:
    """
    构建用于检测页面中加密函数的提示词
    """
    
    prompt = f"""你正在分析一个网页的JavaScript代码，寻找加密和安全相关函数。

**目标URL**: {url}

**页面源码片段** (搜索关键部分):
{page_source[:1000] if page_source else "无源码"}

请识别以下类型的函数：
1. 加密/解密函数（encrypt, decrypt, cipher等）
2. 哈希函数（md5, sha1, sha256等）
3. 编码函数（base64, atob, btoa等）
4. 签名函数（sign, verify, hmac等）
5. 密钥生成函数（generateKey, createKey等）
6. 自定义加密函数（包含位操作、字符串变换等）

输出格式：
{{
    "crypto_functions": [
        {{
            "name": "函数名",
            "type": "加密/哈希/编码/签名/密钥生成",
            "location": "在代码中的位置描述",
            "confidence": "High/Medium/Low"
        }}
    ],
    "recommendations": ["建议对这些函数进行深度分析"]
}}"""
    
    return prompt

def get_network_crypto_analysis_prompt(requests: List[Dict], url: str) -> str:
    """
    构建用于分析网络请求中加密数据的提示词
    """
    
    prompt = f"""你正在分析网页的网络请求，寻找加密通信的证据。

**目标URL**: {url}

**网络请求**:
{json.dumps(requests[:5], indent=2, ensure_ascii=False)}

请分析：
1. 识别可能的加密数据传输
2. 查找密钥交换模式
3. 检测自定义加密协议
4. 识别不安全的传输方式

输出格式：
{{
    "encrypted_requests": [请求URL列表],
    "key_exchange_pattern": "密钥交换模式描述",
    "security_issues": [
        {{
            "type": "问题类型",
            "description": "问题描述",
            "severity": "High/Medium/Low"
        }}
    ]
}}"""
    
    return prompt