"""SSTI (服务器端模板注入) 漏洞分析专用提示词
"""
from typing import Dict, Any

def get_analysis_prompt(context: Dict[str, Any]) -> str:
    """
    构建针对SSTI漏洞分析的提示词
    
    Args:
        context: 包含HTTP请求/响应、参数等信息的上下文
        
    Returns:
        为LLM准备的提示词字符串
    """
    request_url = context.get('url', 'N/A')
    request_params = context.get('params', {})
    response_body = context.get('response_body', '')
    response_headers = context.get('response_headers', {})

    prompt = f"""
你是一名顶级的Web安全专家，尤其擅长通过黑盒测试发现服务器端模板注入 (SSTI) 漏洞。

**分析任务**: 分析以下HTTP交互数据，判断是否存在SSTI漏洞。

**HTTP请求信息**:
- URL: {request_url}
- Parameters: {request_params}

**HTTP响应信息**:
- Headers: {response_headers}
- Body (前500字节):
```html
{response_body[:500]}
```

**分析要求**:
1.  **识别注入点**: 请求参数中，哪个参数的值被反射到了响应体中？
2.  **识别模板引擎特征**: 响应内容或HTTP头中是否包含任何已知模板引擎（如Jinja2, FreeMarker, Velocity等）的特征？
3.  **判断可疑行为**: 当我们注入一个简单的模板表达式（如 `{{7*7}}` 或 `${7*7}`）时，响应中是否出现了预期的计算结果（如 `49`）？或者，响应是否与注入前有显著的不同，暗示了服务器端的解析行为？
4.  **给出结论**: 基于以上分析，判断是否存在SSTI漏洞，并说明你的推理过程和置信度。

**输出格式**: 请以JSON格式返回你的分析报告。
```json
{{
  "vulnerability_detected": "(boolean) 是否检测到漏洞",
  "confidence": "(string) 置信度: High, Medium, Low, or None",
  "reasoning": "(string) 详细的推理过程，解释你的判断依据。",
  "injected_parameter": "(string) 识别出的注入点参数，如果没有则为None",
  "engine_signature": "(string) 识别出的模板引擎特征，如果没有则为None"
}}
```

**重要**: 你的回复必须是严格的JSON格式，不包含任何额外的解释或注释。
"""
    return prompt
