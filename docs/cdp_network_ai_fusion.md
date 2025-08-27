# CDP调试器 + 网络分析 + AI工作流深度融合架构

## 核心理念：深度上下文驱动的智能漏洞挖掘

CDP断点不是负担，而是获取**执行上下文**的利器。结合网络分析，能让AI理解**代码逻辑与数据流**的完整图景。

## 1. 三层协同架构

```
CDP层（执行上下文）
    ↓
网络层（数据流分析）  
    ↓
AI层（智能推理）
```

## 2. 增强的CDP调试器设计

### 2.1 智能断点策略

```python
class IntelligentCDPDebugger:
    """
    智能CDP调试器 - 不是所有操作都设断点
    而是根据上下文智能决定何时深入分析
    """
    
    def __init__(self, output_q: Queue, network_analyzer):
        self.output_q = output_q
        self.network_analyzer = network_analyzer  # 关联网络分析
        self.breakpoint_strategy = BreakpointStrategy()
        self.execution_context = {}
        
    async def setup_intelligent_breakpoints(self, page: Page):
        """设置智能断点 - 关键位置才暂停"""
        cdp = await page.context.new_cdp_session(page)
        
        # 1. 启用调试器
        await cdp.send('Debugger.enable')
        await cdp.send('Runtime.enable')
        await cdp.send('Network.enable')
        
        # 2. 智能断点策略
        # 不是所有事件都设断点，而是关键事件
        critical_events = await self.identify_critical_events(page)
        
        for event in critical_events:
            await cdp.send('DOMDebugger.setEventListenerBreakpoint', {
                'eventName': event,
                'targetName': '*'  # 特定目标
            })
        
        # 3. 监听暂停事件
        cdp.on('Debugger.paused', self.on_intelligent_pause)
        
    async def identify_critical_events(self, page):
        """识别关键事件 - 基于页面分析"""
        
        # 分析页面特征
        page_analysis = await page.evaluate("""
            () => {
                const analysis = {
                    hasLoginForm: !!document.querySelector('input[type="password"]'),
                    hasFileUpload: !!document.querySelector('input[type="file"]'),
                    hasPaymentForm: !!document.querySelector('[name*="card"], [name*="payment"]'),
                    hasApiCalls: !!window.fetch || !!window.XMLHttpRequest,
                    hasCrypto: !!(window.CryptoJS || window.crypto.subtle)
                };
                return analysis;
            }
        """)
        
        critical_events = []
        
        # 根据页面特征决定断点
        if page_analysis['hasLoginForm']:
            critical_events.extend(['submit', 'click'])  # 捕获登录
            
        if page_analysis['hasFileUpload']:
            critical_events.append('change')  # 捕获文件上传
            
        if page_analysis['hasPaymentForm']:
            critical_events.extend(['submit', 'input'])  # 捕获支付
            
        if page_analysis['hasCrypto']:
            # 设置加密函数断点
            await self.set_crypto_breakpoints(cdp)
            
        return critical_events
    
    async def on_intelligent_pause(self, event):
        """智能处理断点暂停"""
        
        # 1. 提取执行上下文
        context = await self.extract_execution_context(event)
        
        # 2. 分析是否涉及敏感操作
        if self.is_sensitive_operation(context):
            # 深度分析
            deep_analysis = await self.deep_analyze(context)
            
            # 3. 关联网络请求
            network_context = await self.network_analyzer.get_related_requests(
                context['timestamp'],
                context['url']
            )
            
            # 4. 合并上下文
            full_context = {
                'execution': context,
                'network': network_context,
                'analysis': deep_analysis
            }
            
            # 5. 发送给AI分析
            await self.output_q.put({
                'type': 'cdp_critical',
                'context': full_context,
                'suggestion': self.generate_test_suggestions(full_context)
            })
        
        # 6. 快速恢复，最小化用户影响
        await self.cdp_session.send('Debugger.resume')
    
    async def extract_execution_context(self, pause_event):
        """提取完整执行上下文"""
        
        call_frames = pause_event.get('callFrames', [])
        
        # 提取关键信息
        context = {
            'call_stack': [],
            'local_variables': {},
            'global_variables': {},
            'crypto_keys': {},
            'api_endpoints': []
        }
        
        for frame in call_frames[:5]:  # 只看前5层
            # 获取局部变量
            scope_chain = frame.get('scopeChain', [])
            for scope in scope_chain:
                if scope['type'] == 'local':
                    # 提取局部变量
                    variables = await self.cdp_session.send('Runtime.getProperties', {
                        'objectId': scope['object']['objectId']
                    })
                    
                    # 智能识别关键变量
                    for var in variables['result']:
                        var_name = var['name']
                        # 识别加密密钥
                        if any(key in var_name.lower() for key in ['key', 'secret', 'token', 'password']):
                            context['crypto_keys'][var_name] = var.get('value', {}).get('value')
                        
                        # 识别API端点
                        if 'url' in var_name.lower() or 'endpoint' in var_name.lower():
                            context['api_endpoints'].append(var.get('value', {}).get('value'))
        
        return context
```

### 2.2 CDP与网络分析的联动

```python
class CDPNetworkFusion:
    """
    CDP和网络分析的深度融合
    """
    
    def __init__(self):
        self.cdp_contexts = {}  # CDP执行上下文
        self.network_requests = []  # 网络请求
        self.correlation_engine = CorrelationEngine()
        
    async def on_cdp_pause(self, cdp_context):
        """CDP断点触发时"""
        
        # 1. 记录执行上下文
        timestamp = time.time()
        self.cdp_contexts[timestamp] = cdp_context
        
        # 2. 查找相关网络请求（前后1秒内）
        related_requests = self.find_related_requests(
            timestamp - 1, 
            timestamp + 1
        )
        
        # 3. 关联分析
        correlation = await self.correlate_cdp_network(
            cdp_context, 
            related_requests
        )
        
        return correlation
    
    async def correlate_cdp_network(self, cdp_context, requests):
        """关联CDP上下文和网络请求"""
        
        correlations = []
        
        # 场景1: 加密参数关联
        if cdp_context.get('crypto_keys'):
            for request in requests:
                # 检查请求是否使用了CDP捕获的密钥
                if self.check_crypto_usage(request, cdp_context['crypto_keys']):
                    correlations.append({
                        'type': 'crypto_correlation',
                        'key': cdp_context['crypto_keys'],
                        'request': request,
                        'vulnerability': 'potential_weak_crypto'
                    })
        
        # 场景2: API端点关联
        for endpoint in cdp_context.get('api_endpoints', []):
            for request in requests:
                if endpoint in request['url']:
                    correlations.append({
                        'type': 'api_correlation',
                        'endpoint': endpoint,
                        'request': request,
                        'context': cdp_context
                    })
        
        # 场景3: 认证流程关联
        if 'login' in cdp_context.get('function_name', '').lower():
            auth_requests = [r for r in requests if 'auth' in r['url'] or 'login' in r['url']]
            if auth_requests:
                correlations.append({
                    'type': 'auth_flow',
                    'cdp_context': cdp_context,
                    'requests': auth_requests,
                    'test_vectors': self.generate_auth_test_vectors(cdp_context, auth_requests)
                })
        
        return correlations
```

## 3. 网络层增强 - 与CDP协同

```python
class EnhancedNetworkAnalyzer:
    """
    增强的网络分析器，与CDP深度集成
    """
    
    def __init__(self):
        self.request_history = []
        self.response_cache = {}
        self.pattern_matcher = PatternMatcher()
        
    async def intercept_and_analyze(self, request, cdp_context=None):
        """拦截并分析请求，结合CDP上下文"""
        
        # 1. 基础分析
        analysis = {
            'url': request.url,
            'method': request.method,
            'headers': dict(request.headers),
            'body': request.post_data
        }
        
        # 2. 如果有CDP上下文，深度分析
        if cdp_context:
            # 检查请求参数是否来自CDP捕获的变量
            analysis['parameter_source'] = self.trace_parameter_source(
                request, 
                cdp_context
            )
            
            # 检查是否使用了加密
            if cdp_context.get('crypto_keys'):
                analysis['encryption'] = self.analyze_encryption(
                    request.post_data,
                    cdp_context['crypto_keys']
                )
        
        # 3. 智能变异建议
        analysis['mutation_suggestions'] = await self.generate_mutations(
            request,
            cdp_context
        )
        
        return analysis
    
    async def generate_mutations(self, request, cdp_context):
        """基于CDP上下文生成智能变异"""
        
        mutations = []
        
        # 如果CDP显示有加密
        if cdp_context and cdp_context.get('crypto_keys'):
            # 生成加密相关的测试
            mutations.extend([
                {
                    'type': 'weak_key',
                    'description': '测试弱密钥',
                    'payload': self.generate_weak_key_payload(cdp_context['crypto_keys'])
                },
                {
                    'type': 'key_reuse',
                    'description': '测试密钥重用',
                    'payload': self.test_key_reuse(cdp_context['crypto_keys'])
                }
            ])
        
        # 如果CDP显示有认证逻辑
        if cdp_context and 'auth' in str(cdp_context.get('call_stack', '')):
            mutations.extend([
                {
                    'type': 'auth_bypass',
                    'description': '认证绕过测试',
                    'payload': self.generate_auth_bypass_payload(request)
                },
                {
                    'type': 'privilege_escalation',
                    'description': '权限提升测试',
                    'payload': self.generate_privilege_escalation_payload(request)
                }
            ])
        
        return mutations
```

## 4. AI工作流集成 - 理解完整上下文

```python
class ContextAwareAIWorker:
    """
    上下文感知的AI工作器
    能理解CDP执行上下文 + 网络数据流
    """
    
    def __init__(self, llm_client, vector_db):
        self.llm_client = llm_client
        self.vector_db = vector_db
        self.context_builder = ContextBuilder()
        
    async def analyze_with_full_context(self, cdp_context, network_context):
        """基于完整上下文的AI分析"""
        
        # 1. 构建完整上下文
        full_context = self.context_builder.build(
            cdp_context,
            network_context
        )
        
        # 2. 生成智能提示词
        prompt = self.generate_analysis_prompt(full_context)
        
        # 3. AI推理
        ai_response = await self.llm_client.complete(prompt)
        
        # 4. 解析AI建议
        analysis = self.parse_ai_response(ai_response)
        
        # 5. 生成具体测试用例
        test_cases = await self.generate_test_cases(analysis, full_context)
        
        return {
            'analysis': analysis,
            'test_cases': test_cases,
            'confidence': self.calculate_confidence(analysis, full_context)
        }
    
    def generate_analysis_prompt(self, context):
        """生成分析提示词"""
        
        prompt = f"""
        你是一个安全专家，正在分析一个Web应用的安全性。
        
        ## CDP执行上下文
        - 调用栈: {context['cdp']['call_stack']}
        - 局部变量: {context['cdp']['local_variables']}
        - 发现的密钥: {context['cdp'].get('crypto_keys', 'None')}
        - API端点: {context['cdp'].get('api_endpoints', [])}
        
        ## 网络请求上下文
        - 请求URL: {context['network']['url']}
        - 请求方法: {context['network']['method']}
        - 请求体: {context['network']['body']}
        - 响应状态: {context['network']['response_status']}
        
        ## 关联分析
        - 参数来源: {context.get('parameter_source', 'Unknown')}
        - 加密使用: {context.get('encryption', 'None')}
        
        基于以上信息，请分析：
        1. 可能存在的安全漏洞
        2. 漏洞的利用链
        3. 具体的测试方法
        4. 预期的响应特征
        
        请以JSON格式返回你的分析结果。
        """
        
        return prompt
    
    async def generate_test_cases(self, analysis, context):
        """生成具体测试用例"""
        
        test_cases = []
        
        for vulnerability in analysis.get('vulnerabilities', []):
            if vulnerability['type'] == 'crypto_weakness':
                # 基于CDP捕获的密钥生成测试
                test_cases.append(
                    self.generate_crypto_test(
                        context['cdp']['crypto_keys'],
                        context['network']
                    )
                )
            
            elif vulnerability['type'] == 'auth_bypass':
                # 基于执行流程生成绕过测试
                test_cases.append(
                    self.generate_auth_bypass_test(
                        context['cdp']['call_stack'],
                        context['network']
                    )
                )
            
            elif vulnerability['type'] == 'idor':
                # 基于参数来源生成IDOR测试
                test_cases.append(
                    self.generate_idor_test(
                        context['parameter_source'],
                        context['network']
                    )
                )
        
        return test_cases
```

## 5. Shadow Browser集成 - 执行AI生成的测试

```python
class ShadowTestExecutor:
    """
    在Shadow Browser中执行AI生成的测试
    """
    
    def __init__(self, browser_pool):
        self.browser_pool = browser_pool
        self.test_queue = asyncio.Queue()
        self.result_collector = ResultCollector()
        
    async def execute_ai_tests(self, test_cases, original_context):
        """执行AI生成的测试用例"""
        
        results = []
        
        # 获取Shadow Browser
        shadow_browser = await self.browser_pool.acquire_shadow()
        
        # 恢复原始上下文（认证、cookies等）
        await self.restore_context(shadow_browser, original_context)
        
        for test in test_cases:
            try:
                # 根据测试类型执行
                if test['type'] == 'crypto_attack':
                    result = await self.execute_crypto_attack(
                        shadow_browser,
                        test,
                        original_context['cdp']['crypto_keys']
                    )
                    
                elif test['type'] == 'auth_bypass':
                    result = await self.execute_auth_bypass(
                        shadow_browser,
                        test
                    )
                    
                elif test['type'] == 'api_fuzzing':
                    result = await self.execute_api_fuzzing(
                        shadow_browser,
                        test,
                        original_context['network']
                    )
                
                results.append(result)
                
                # 如果发现漏洞，立即深入测试
                if result['success']:
                    deep_tests = await self.generate_deep_tests(result, test)
                    for deep_test in deep_tests:
                        deep_result = await self.execute_test(shadow_browser, deep_test)
                        results.append(deep_result)
                        
            except Exception as e:
                self.logger.error(f"Test execution failed: {e}")
        
        return results
    
    async def execute_crypto_attack(self, browser, test, original_keys):
        """执行加密攻击测试"""
        
        # 1. 修改加密密钥
        await browser.evaluate(f"""
            // 尝试覆盖原始密钥
            window.{test['key_variable']} = '{test['malicious_key']}';
        """
        
        # 2. 触发加密操作
        await browser.click(test['trigger_selector'])
        
        # 3. 拦截请求
        request = await browser.wait_for_request(test['expected_endpoint'])
        
        # 4. 分析结果
        return {
            'success': request.status == 200,
            'type': 'weak_crypto',
            'details': {
                'original_key': original_keys,
                'injected_key': test['malicious_key'],
                'response': request.response
            }
        }
```

## 6. 完整攻击链示例

### 场景：登录表单with AES加密

```python
# Step 1: 用户访问登录页面
用户 → 浏览器: 访问 /login

# Step 2: CDP检测到加密库
CDP断点 → 捕获:
  - window.CryptoJS存在
  - 发现AES_KEY = "1234567890123456"
  - 调用栈显示: encrypt() → login() → submit()

# Step 3: 用户输入并提交
用户 → 输入: username="admin", password="123456"
CDP断点 → 捕获:
  - 局部变量: plaintext = "admin:123456"
  - 加密调用: CryptoJS.AES.encrypt(plaintext, AES_KEY)

# Step 4: 网络层拦截
Network → 捕获:
  POST /api/login
  Body: {"data": "U2FsdGVkX1+..."}  # 加密的payload

# Step 5: AI分析
AI → 推理:
  - 发现: 使用硬编码AES密钥
  - 漏洞: 密钥可被提取和重用
  - 建议: 测试密钥重用攻击

# Step 6: Shadow Browser执行测试
Shadow → 测试1: 使用捕获的密钥构造admin请求
  - 构造: {"data": encrypt("admin:admin", AES_KEY)}
  - 结果: ✅ 登录成功

Shadow → 测试2: 枚举其他用户
  - 构造: {"data": encrypt("user2:123456", AES_KEY)}
  - 结果: ✅ 可枚举用户

# Step 7: 确认漏洞链
漏洞链:
  1. 硬编码密钥暴露 (CDP捕获)
  2. 可预测的加密 (网络分析)
  3. 用户枚举 (Shadow测试)
  4. 潜在的账户接管

# Step 8: 用户体验
用户: 正常登录，完全无感知
系统: 发现并验证了完整的攻击链
```

## 7. 优化策略

### 7.1 最小化用户影响

```python
class MinimalImpactStrategy:
    """最小化CDP断点对用户的影响"""
    
    def __init__(self):
        self.pause_threshold = 50  # 最大暂停时间(ms)
        self.pause_count = {}  # 记录每个事件的暂停次数
        
    async def should_pause(self, event_type, context):
        """决定是否应该暂停"""
        
        # 1. 检查是否已经分析过类似上下文
        if self.is_similar_context_analyzed(context):
            return False
        
        # 2. 检查暂停频率
        if self.pause_count.get(event_type, 0) > 3:
            # 同一事件暂停超过3次，跳过
            return False
        
        # 3. 检查是否是关键操作
        if not self.is_critical_operation(context):
            return False
        
        return True
    
    async def quick_extract_and_resume(self, cdp_session, pause_event):
        """快速提取信息并恢复"""
        
        start_time = time.time()
        
        # 并行提取所有需要的信息
        tasks = [
            self.extract_variables(cdp_session, pause_event),
            self.extract_call_stack(cdp_session, pause_event),
            self.extract_network_state(cdp_session)
        ]
        
        results = await asyncio.gather(*tasks)
        
        # 立即恢复执行
        await cdp_session.send('Debugger.resume')
        
        elapsed = (time.time() - start_time) * 1000
        
        if elapsed > self.pause_threshold:
            self.logger.warning(f"Pause took {elapsed}ms, exceeding threshold")
        
        return {
            'variables': results[0],
            'call_stack': results[1],
            'network': results[2],
            'pause_duration_ms': elapsed
        }
```

### 7.2 智能缓存

```python
class ContextCache:
    """缓存CDP上下文，避免重复分析"""
    
    def __init__(self):
        self.cache = {}
        self.similarity_threshold = 0.8
        
    def get_similar_context(self, context):
        """查找相似的已分析上下文"""
        
        context_hash = self.compute_context_hash(context)
        
        for cached_hash, cached_result in self.cache.items():
            similarity = self.compute_similarity(context_hash, cached_hash)
            if similarity > self.similarity_threshold:
                return cached_result
        
        return None
    
    def compute_context_hash(self, context):
        """计算上下文指纹"""
        
        # 基于关键特征生成hash
        features = [
            context.get('function_name'),
            context.get('url'),
            tuple(context.get('api_endpoints', [])),
            bool(context.get('crypto_keys'))
        ]
        
        return hash(tuple(features))
```

## 8. 实施优先级

1. **保留并增强CDP调试器** - 智能断点策略
2. **实现CDP-网络关联引擎** - 关联执行上下文和网络请求
3. **增强AI分析能力** - 理解完整上下文
4. **优化用户体验** - 最小化暂停时间
5. **添加智能缓存** - 避免重复分析

这样的设计真正实现了CDP、网络和AI的有机结合，能够挖掘出复杂的逻辑漏洞！

---
## 核心机制：通过“交互关联ID”实现上下文的重建与合成

### 问题背景
AI模型本身是“无状态”的，它无法像人类一样“记住”一个操作的完整过程。而安全分析恰恰需要理解一个有时序、有因果的复杂上下文（例如：用户A点击了按钮B，触发了函数C的调用，函数C又调用了函数D，最终发出了网络请求E）。本机制旨在解决这个核心矛盾。

**核心思想**：我们不强迫AI去“记住”事件流，而是为AI**“重建”和“合成”一个完整的、包含所有因果关系的结构化上下文快照**。我们不给AI看零散的事件，而是给它看一张“犯罪现场的全景照片”。

### 第1步：事件捕获与标记 (The Collector)
这是信息收集的前端。当用户产生一次关键交互（比如点击登录按钮）时，系统会立即生成一个唯一的 **“交互关联ID” (Interaction Correlation ID - ICID)**，例如 `icid-click-login-1678886400`。

然后，系统会开启一个短暂的 **“收集窗口”**（比如3秒）。在此窗口内，所有不同的探针捕获到的事件，都会被**强制标记**上这个激活的ICID。

- **`CDPController`**: 捕获到`click`事件，标记上ICID。
- **`CDPDebugger`**: 在接下来的几百毫秒内，可能会因为JS执行而触发多次`Debugger.paused`事件（例如，`login()` -> `validate()` -> `encrypt()`），**每一次暂停**事件都会被标记上**同一个ICID**。
- **`unified_hooks.js` (IAST+JS逆向)**: 如果`innerHTML`或`eval`等危险函数被调用，或者加密函数被执行，探针会上报一个安全警报，这个警报也会被标记上同一个ICID。
- **网络监听器**: 所有在这期间发出的网络请求（`Network.requestWillBeSent`），同样被标记上ICID。

所有这些被标记的、类型各异的原始事件，都被统一扔进一个原始事件队列中。

### 第2步：事件关联与分组 (The Correlator)
后台有一个专门的`CorrelationWorker`。它的工作很简单：从原始事件队列中取出事件，然后按照它们的`ICID`进行分组。

当一个ICID的收集窗口（3秒）结束后，`CorrelationWorker`就得到了与“用户那一次点击”相关的所有事件的完整集合。这个集合就是我们分析的基础。

### 第3. 上下文合成与结构化 (The Synthesizer)
这是最关键的一步。`CorrelationWorker`拿到一个ICID的事件组后，并不直接把它们丢给AI，而是进行“合成”，生成一个高度结构化的 **“关联交互快照 (Correlated Interaction Snapshot)”**。

这个快照的结构大概是这样的：
```json
{
  "interaction_correlation_id": "icid-click-login-12345",
  "trigger_event": {
    "type": "click",
    "selector": "button#login-btn",
    "timestamp": "2023-03-15T12:00:00.000Z"
  },
  "synthesized_context": {
    "call_tree": {
      "function": "login_handler",
      "variables": [{"name": "username", "value": "admin"}],
      "children": [
        {
          "function": "encrypt_password",
          "variables": [{"name": "plaintext", "value": "admin_password"}],
          "children": []
        }
      ]
    },
    "network_requests": [
      {
        "url": "/api/login",
        "method": "POST",
        "payload": {"data": "U2FsdGVkX1..."},
        "triggered_by_function": "login_handler" 
      }
    ],
    "iast_alerts": [
      {
        "sink": "innerHTML",
        "value": "欢迎, admin!",
        "triggered_by_function": "update_welcome_message"
      }
    ]
  },
  "raw_event_timeline": [ /* ... 原始事件列表 ... */ ]
}
```

**如何应对复杂函数连续调用？**

这就是`call_tree`字段的作用。当`Synthesizer`处理一个ICID的事件组时，如果发现有多个`Debugger.paused`事件，它会：
1.  根据CDP提供的调用栈信息（`callFrames`），重建出这些暂停事件之间的父子关系。
2.  `login_handler`的暂停是第一次，成为树的根。
3.  `encrypt_password`的暂停是第二次，且位于`login_handler`的调用栈之内，所以成为它的子节点。
4.  通过这种方式，**我们将一个扁平的事件列表，转换成了一个能反映真实执行逻辑的、有层次的树状结构**。AI看到这个树，就能立刻明白函数的调用关系。

### 第4步：AI分析 (The Analyzer)
最后，这个**经过合成的、结构化的“关联交互快照”**，作为一个完整的JSON对象，被送入AI的`prompt`中。

现在，我们给AI的指令不再是“请分析这些零散的事件”，而是：

> “你是一名安全专家。当用户点击了登录按钮后，我们捕获到了一个完整的交互快照。快照显示，`login_handler`函数被调用，它内部又调用了`encrypt_password`函数，并最终触发了一个到`/api/login`的POST请求。请基于这个完整的因果链，分析是否存在安全漏洞。”

通过这个流程，我们**用一个外部的、强大的“合成器”程序，为无状态的AI预处理好了一切**。AI不需要自己去记忆和关联，它只需要在拿到这张“全景照片”后，发挥它最擅长的、基于复杂上下文的推理能力即可。