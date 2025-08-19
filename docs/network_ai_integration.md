# 网络分析与AI协同优化方案

## 核心理念
保持AI的"用户无感"主动探索特性，将网络分析作为AI的"感知器官"，而非替代AI决策。

## 1. 网络工具作为AI的"眼睛"

### 原则：
- 网络工具只提供**结构化观察**，不做决策
- AI根据观察结果**主动推理**下一步
- 保持工具调用的**原子性**和**可组合性**

### 实现方式：

#### A. 增强 `send_custom_request` 为智能观察器
```python
async def send_custom_request(url, method, **kwargs) -> Dict:
    """发送请求并返回结构化观察结果"""
    response = await httpx_request(url, method, **kwargs)
    
    return {
        "raw": response,  # 原始响应
        "observations": {  # AI可理解的观察
            "status_pattern": classify_status(response.status),
            "data_exposure": detect_sensitive_data(response.body),
            "auth_indicators": detect_auth_patterns(response),
            "error_leaks": detect_error_info(response),
            "timing_anomaly": response.elapsed > 5000
        },
        "hints": generate_next_step_hints(response)  # 提示可能的下一步
    }
```

#### B. 新增请求序列分析器
```python
async def analyze_request_sequence(page: Page) -> Dict:
    """分析最近的请求序列，识别模式"""
    recent_requests = get_recent_requests()
    
    return {
        "patterns": {
            "auth_flow": detect_auth_flow(recent_requests),
            "api_structure": infer_api_structure(recent_requests),
            "id_patterns": extract_id_patterns(recent_requests)
        },
        "anomalies": detect_anomalies(recent_requests),
        "correlation_hints": suggest_correlations(recent_requests)
    }
```

## 2. 将网络分析融入AI决策流程

### 修改 prompt.py 中的工具定义：

```python
AVAILABLE_TOOLS = {
    # ... 现有工具 ...
    
    "send_custom_request": {
        "description": "发送HTTP请求并获取智能分析结果。返回响应和安全观察。",
        "args": {
            "url": "(string) 目标URL",
            "method": "(string) HTTP方法",
            "headers": "(dict, optional) 请求头",
            "params": "(dict, optional) URL参数",
            "json_data": "(dict, optional) JSON数据"
        },
        "returns": "包含raw响应、observations（安全观察）、hints（下一步建议）"
    },
    
    "analyze_request_sequence": {
        "description": "分析最近的请求序列，发现API模式和异常。",
        "args": {},
        "returns": "请求模式分析、异常检测、关联提示"
    },
    
    "test_auth_vectors": {
        "description": "智能测试认证绕过向量。自动尝试多种技术。",
        "args": {"url": "(string) 目标端点"},
        "returns": "绕过测试结果和漏洞确认"
    },
    
    "probe_idor_pattern": {
        "description": "探测IDOR模式。智能识别ID参数并测试越权。",
        "args": {"url_pattern": "(string) 包含{id}占位符的URL"},
        "returns": "IDOR测试结果和数据泄露分析"
    }
}
```

### 增强AI推理提示词：

```python
def get_enhanced_reasoning_prompt(goal, state, sast, iast, network_obs):
    """增强的推理提示词，包含网络观察"""
    
    # 新增网络观察部分
    network_section = """
    **🌐 网络层观察**:
    最近请求的模式：
    - API结构: {api_structure}
    - 认证流程: {auth_flow}
    - 异常响应: {anomalies}
    
    关键发现：
    - 数据泄露风险: {data_exposure}
    - 错误信息暴露: {error_leaks}
    - 时序异常: {timing_anomalies}
    
    建议的测试向量：
    {suggested_vectors}
    """
    
    # 在原有prompt基础上添加网络观察
    return original_prompt + network_section
```

## 3. CDP调试器与网络分析的协同

### 场景：登录表单加密分析

```python
class EnhancedCDPDebugger:
    async def capture_crypto_context(self, event):
        """捕获加密函数的执行上下文"""
        if 'encrypt' in event.get('functionName', '').lower():
            # 提取加密相关的变量
            crypto_vars = await self.cdp_session.send(
                'Runtime.evaluate',
                {'expression': 'JSON.stringify({key: window.AES_KEY, iv: window.AES_IV})'}
            )
            
            # 通知AI发现了加密上下文
            await self.output_q.put({
                'type': 'crypto_context',
                'data': crypto_vars,
                'suggestion': 'use_this_for_custom_request'
            })
```

## 4. 实战工作流示例

### 复杂漏洞挖掘流程：

```python
# Step 1: AI观察登录表单
ai_decision = {
    "thought": "发现登录表单，需要分析加密机制",
    "tool_call": {"name": "get_crypto_functions"}
}

# Step 2: 发现AES加密
crypto_info = {
    "crypto_libraries": ["CryptoJS"],
    "potential_keys": {"AES_KEY": "1234567890abcdef"}
}

# Step 3: AI决定拦截请求
ai_decision = {
    "thought": "发现AES加密，需要拦截实际请求",
    "tool_call": {"name": "intercept_network_requests", "args": {"duration_ms": 5000}}
}

# Step 4: 捕获登录API
intercepted = {
    "api_endpoints": ["/api/login"],
    "post_data": "encrypted_payload"
}

# Step 5: AI尝试构造请求
ai_decision = {
    "thought": "发现登录API，尝试未授权访问",
    "tool_call": {
        "name": "send_custom_request",
        "args": {
            "url": "/api/users",
            "method": "GET",
            "headers": {}
        }
    }
}

# Step 6: 网络工具返回智能观察
response = {
    "raw": {"status_code": 200, "body": "[{user1}, {user2}]"},
    "observations": {
        "data_exposure": "mass_user_data",
        "auth_indicators": "no_auth_required"
    },
    "hints": ["critical_unauth_access", "test_other_endpoints"]
}

# Step 7: AI确认漏洞并深入测试
ai_decision = {
    "thought": "确认未授权访问漏洞！返回了用户列表。继续测试IDOR",
    "tool_call": {"name": "probe_idor_pattern", "args": {"url_pattern": "/api/user/{id}"}}
}
```

## 5. 关键优化点

### A. 请求上下文追踪
```python
class RequestContextTracker:
    """追踪请求上下文，供AI分析"""
    
    def __init__(self):
        self.session_tokens = {}
        self.api_patterns = {}
        self.auth_flows = []
    
    async def track_request(self, request, response):
        # 提取session/token
        if 'Set-Cookie' in response.headers:
            self.extract_session(response.headers['Set-Cookie'])
        
        # 识别API模式
        self.learn_api_pattern(request.url, response)
        
        # 记录认证流程
        if response.status in [401, 403, 200]:
            self.record_auth_flow(request, response)
    
    def get_context_for_ai(self):
        """生成AI可理解的上下文摘要"""
        return {
            "active_sessions": list(self.session_tokens.keys()),
            "api_patterns": self.api_patterns,
            "auth_flow_stage": self.infer_auth_stage()
        }
```

### B. 智能请求变异器
```python
async def mutate_request_intelligent(base_request, mutation_type):
    """智能变异请求，用于fuzzing"""
    
    mutations = {
        "auth_bypass": [
            {"headers": {}},  # 删除认证头
            {"headers": {"X-Forwarded-For": "127.0.0.1"}},
            {"params": {"admin": "true"}}
        ],
        "idor": [
            {"url": increment_id(base_request.url)},
            {"url": decrement_id(base_request.url)},
            {"url": replace_id(base_request.url, 0)}
        ],
        "injection": [
            {"params": add_sqli_payload(base_request.params)},
            {"json_data": add_xss_payload(base_request.json_data)}
        ]
    }
    
    return mutations.get(mutation_type, [])
```

## 6. 与现有架构的无缝集成

### 修改 agent_worker.py：

```python
class AgentWorker:
    def __init__(self, ...):
        # 新增网络上下文追踪器
        self.request_tracker = RequestContextTracker()
    
    async def run(self):
        for step in range(10):
            # ... 现有SAST/IAST分析 ...
            
            # 新增：获取网络上下文
            network_context = self.request_tracker.get_context_for_ai()
            
            # 增强推理prompt
            reasoning_prompt = get_enhanced_reasoning_prompt(
                self.goal, 
                self.working_memory,
                sast_results,
                current_iast_findings,
                self.long_term_memories,
                network_context  # 新增网络上下文
            )
            
            # AI决策
            ai_decision = await self._call_llm(reasoning_prompt)
            
            # 执行工具调用
            if tool_name == "send_custom_request":
                # 使用增强的网络工具
                response = await enhanced_send_custom_request(...)
                # 更新请求追踪器
                await self.request_tracker.track_request(...)
```

## 7. 预期效果

1. **更智能的漏洞发现**：
   - AI能理解请求间的关联
   - 自动识别认证流程并测试绕过
   - 智能推断API结构并系统性测试

2. **更深入的分析**：
   - 结合CDP捕获的加密上下文
   - 关联多个请求构建攻击链
   - 识别复杂的逻辑漏洞

3. **保持AI主导**：
   - 网络工具只提供观察，不做决策
   - AI根据上下文主动探索
   - 用户完全无感知

## 8. 实施步骤

1. **第一阶段**：增强`network_tools.py`，添加智能观察功能
2. **第二阶段**：实现`RequestContextTracker`，追踪请求上下文
3. **第三阶段**：修改`prompt.py`，添加网络观察的提示
4. **第四阶段**：更新`agent_worker.py`，集成网络上下文
5. **第五阶段**：优化CDP调试器，与网络分析协同

这样的设计保持了AI的主动探索特性，同时大大增强了其"感知"能力，使其能够发现和利用更复杂的漏洞。
