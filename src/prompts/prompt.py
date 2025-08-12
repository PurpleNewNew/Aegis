"""
用于集中存储和生成LLM提示词的模块。
"""

def get_soft_vuln_prompt(context: dict, memories: dict) -> str:
    """
    为软漏洞分析构建详细的LLM提示词。
    """
    prompt = f"""你是一名专攻前端和业务逻辑漏洞的Web安全专家。
请分析以下网络请求中潜在的安全缺陷。
请专注于分析诸如跨站脚本（XSS）、不安全的直接对象引用（IDOR）、权限绕过和业务逻辑错误等问题。\n\n--- 当前请求上下文 ---\n
URL: {context.get('url')}

方法: {context.get('method')}

请求头: {context.get('headers')}

POST数据 (Hex): {context.get('post_data')}\n\n"""

    if memories and memories.get('documents') and memories['documents'][0]:
        prompt += "--- 相关历史分析（记忆） ---\n"
        for mem in memories['documents'][0]:
            prompt += f"- {mem}\n"
        prompt += "\n"

    prompt += (
        "--- 分析任务 ---\n" 
        "1. 基于请求数据和历史背景，识别潜在的漏洞。\n" 
        "2. 对每一个发现，请简要解释该漏洞，说明其潜在影响（严重性：低/中/高/危急），并给出你的置信度（百分比表示）。\n" 
        "3. 如果未发现漏洞，请明确指出‘未识别出软漏洞’。\n" 
        "4. 请清晰地格式化你的回答。"
    )
    return prompt

def get_hard_vuln_prompt(context: dict, memories: dict) -> str:
    """
    为硬漏洞/后端漏洞分析构建详细的LLM提示词。
    """
    prompt = f"""你是一名在逆向工程和识别后端漏洞方面经验丰富的Web安全研究员。
请分析以下网络请求，以**被动推断**潜在的服务器端缺陷。
**不要建议发送任何数据包或攻击载荷。**你的任务是基于API端点的结构和参数来猜测漏洞。\n\n--- 当前请求上下文 ---\n
URL: {context.get('url')}

方法: {context.get('method')}

请求头: {context.get('headers')}

POST数据 (Hex): {context.get('post_data')}\n\n"""

    if memories and memories.get('documents') and memories['documents'][0]:
        prompt += "--- 相关历史分析（记忆） ---\n"
        for mem in memories['documents'][0]:
            prompt += f"- {mem}\n"
        prompt += "\n"

    prompt += (
        "--- 分析任务 ---\n" 
        "1. 被动地分析请求。寻找可能暗示SQL注入、远程代码执行（RCE）、服务端请求伪造（SSRF）或不安全的反序列化等漏洞的模式（例如，可疑的API端点名称、查询参数、数据格式等）。\n" 
        "2. 对每一个**可疑的**漏洞，解释你的推理过程。评估其严重性（低/中/高/危急）和你的置信度（百分比表示）。\n" 
        "3. 如果未发现此类模式，请明确指出‘未识别出硬漏洞模式’。\n" 
        "4. 请清晰地格式化你的回答。"
    )
    return prompt