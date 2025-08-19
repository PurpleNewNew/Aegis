# Shadow Browser - 真正的用户无感深度测试方案

## 🎯 核心理念：完全隐形的深度测试

用户以为只是在正常浏览，实际上Shadow Browser在暗中：
1. **镜像用户操作** - 在隐藏的浏览器上下文中复制用户行为
2. **智能变异测试** - 对每个用户操作进行安全变异测试
3. **时间差攻击** - 利用用户操作间隙进行深度fuzzing
4. **上下文继承** - 自动继承用户的认证状态和会话

## 1. Shadow Browser 架构

```
用户浏览器 (可见)
    ↓ [CDP监听]
    ↓ 捕获所有用户操作
    ↓
Shadow Browser Pool (不可见)
    ├── Shadow Instance 1: 复制用户操作
    ├── Shadow Instance 2: 变异测试
    ├── Shadow Instance 3: 深度fuzzing
    └── Shadow Instance N: 并行探索
```

## 2. 核心实现：ShadowBrowserController

```python
class ShadowBrowserController:
    """
    完全隐形的深度测试控制器
    用户完全无感知，但实际进行了全面的安全测试
    """
    
    def __init__(self, config):
        self.shadow_pool = []  # 影子浏览器池
        self.user_actions_queue = Queue()  # 用户操作队列
        self.test_results = []  # 测试结果（静默收集）
        self.user_context = {}  # 用户上下文（认证、cookies等）
        
    async def mirror_user_action(self, action):
        """
        镜像用户操作到影子浏览器
        关键：完全异步，不影响用户体验
        """
        # 1. 记录用户操作
        await self.user_actions_queue.put(action)
        
        # 2. 异步分发到影子浏览器
        asyncio.create_task(self._shadow_test(action))
        
        # 3. 立即返回，不等待测试完成
        return
    
    async def _shadow_test(self, action):
        """在影子浏览器中进行深度测试"""
        shadow_browser = await self.get_shadow_browser()
        
        # 复制用户状态
        await shadow_browser.set_context(self.user_context)
        
        # 执行变异测试
        test_variants = self.generate_test_variants(action)
        for variant in test_variants:
            await shadow_browser.execute(variant)
            
        # 静默收集结果
        self.collect_results(shadow_browser)
```

## 3. 用户操作捕获与镜像

### A. CDP Hook - 完全透明的操作捕获

```python
class TransparentCDPHook:
    """透明捕获用户所有操作"""
    
    async def setup(self, user_page):
        """在用户页面上设置透明hook"""
        cdp = await user_page.context.new_cdp_session(user_page)
        
        # 监听所有用户事件
        await cdp.send('Runtime.enable')
        await cdp.send('DOM.enable')
        await cdp.send('Network.enable')
        
        # 设置事件监听（不设断点，避免影响用户）
        cdp.on('DOM.documentUpdated', self.on_dom_change)
        cdp.on('Network.requestWillBeSent', self.on_request)
        cdp.on('Runtime.consoleAPICalled', self.on_console)
        
    async def on_user_click(self, event):
        """捕获用户点击"""
        # 记录点击目标和上下文
        action = {
            'type': 'click',
            'selector': event['selector'],
            'url': event['url'],
            'timestamp': time.time()
        }
        
        # 立即镜像到Shadow Browser
        await shadow_controller.mirror_user_action(action)
        
    async def on_user_input(self, event):
        """捕获用户输入"""
        action = {
            'type': 'input',
            'selector': event['selector'],
            'value': event['value'],  # 注意：敏感数据处理
            'url': event['url']
        }
        
        # 生成测试变体（不使用真实密码）
        test_action = self.sanitize_sensitive_input(action)
        await shadow_controller.mirror_user_action(test_action)
```

### B. 智能测试变体生成

```python
class TestVariantGenerator:
    """为每个用户操作生成测试变体"""
    
    def generate_variants(self, user_action):
        """
        基于用户操作生成安全测试变体
        关键：智能且全面，但不影响用户
        """
        variants = []
        
        if user_action['type'] == 'click':
            # 点击操作的变体
            variants.extend([
                # 权限测试
                {'...action', 'headers': {}},  # 无认证点击
                {'...action', 'user_id': 'other'},  # 其他用户身份
                
                # 参数污染
                {'...action', 'params': {'admin': 'true'}},
                {'...action', 'params': {'debug': '1'}},
            ])
            
        elif user_action['type'] == 'input':
            # 输入操作的变体
            selector = user_action['selector']
            
            # 根据输入框类型生成payload
            if 'search' in selector or 'query' in selector:
                variants.extend([
                    {'...action', 'value': '<script>alert(1)</script>'},
                    {'...action', 'value': "' OR '1'='1"},
                    {'...action', 'value': '{{7*7}}'},  # SSTI
                ])
            elif 'email' in selector:
                variants.extend([
                    {'...action', 'value': 'admin@admin.com'},
                    {'...action', 'value': "test'@test.com"},
                ])
            elif 'url' in selector:
                variants.extend([
                    {'...action', 'value': 'javascript:alert(1)'},
                    {'...action', 'value': 'http://evil.com'},
                ])
                
        elif user_action['type'] == 'navigation':
            # 导航操作的变体
            url = user_action['url']
            variants.extend([
                # IDOR测试
                self.generate_idor_variant(url),
                # 路径遍历
                self.generate_path_traversal_variant(url),
                # API探测
                self.generate_api_discovery_variant(url)
            ])
            
        return variants
```

## 4. Shadow Browser 执行策略

### A. 时间差利用 - 智能调度

```python
class ShadowScheduler:
    """
    智能调度Shadow Browser的测试
    利用用户操作间隙进行深度测试
    """
    
    def __init__(self):
        self.user_idle_threshold = 2.0  # 用户空闲阈值（秒）
        self.last_user_action = time.time()
        self.pending_tests = PriorityQueue()
        
    async def schedule_test(self, test):
        """调度测试任务"""
        priority = self.calculate_priority(test)
        await self.pending_tests.put((priority, test))
        
        # 如果用户空闲，立即执行
        if self.is_user_idle():
            await self.execute_batch_tests()
    
    def is_user_idle(self):
        """检测用户是否空闲"""
        return time.time() - self.last_user_action > self.user_idle_threshold
    
    async def execute_batch_tests(self):
        """批量执行测试（用户空闲时）"""
        batch_size = min(self.pending_tests.qsize(), 10)
        
        tasks = []
        for _ in range(batch_size):
            if not self.pending_tests.empty():
                _, test = await self.pending_tests.get()
                tasks.append(self.run_shadow_test(test))
        
        # 并行执行
        await asyncio.gather(*tasks, return_exceptions=True)
```

### B. 上下文同步 - 自动继承认证

```python
class ContextSynchronizer:
    """
    自动同步用户认证状态到Shadow Browser
    确保测试在正确的权限上下文中进行
    """
    
    async def sync_auth_state(self, user_browser, shadow_browser):
        """同步认证状态"""
        # 提取用户的cookies、localStorage、sessionStorage
        user_state = await user_browser.context.storage_state()
        
        # 应用到shadow browser
        await shadow_browser.context.add_cookies(user_state['cookies'])
        
        # 同步localStorage和sessionStorage
        await shadow_browser.evaluate('''
            (state) => {
                // 恢复localStorage
                for (let key in state.localStorage) {
                    localStorage.setItem(key, state.localStorage[key]);
                }
                // 恢复sessionStorage
                for (let key in state.sessionStorage) {
                    sessionStorage.setItem(key, state.sessionStorage[key]);
                }
            }
        ''', user_state)
        
    async def monitor_auth_changes(self, user_browser):
        """监控认证状态变化"""
        # 监听cookie变化
        user_browser.on('response', async (response) => {
            if 'set-cookie' in response.headers:
                # 认证状态可能已改变
                await self.trigger_resync()
        })
```

## 5. 深度测试场景

### A. 表单提交劫持与变异

```python
async def shadow_form_test(form_data, shadow_browser):
    """
    用户提交表单时，Shadow Browser同时测试多个变体
    """
    
    # 原始表单数据
    original = form_data.copy()
    
    # 测试变体
    test_cases = [
        # XSS in every field
        {**original, field: f"{value}<script>alert(1)</script>" 
         for field, value in original.items()},
        
        # SQL Injection
        {**original, field: f"{value}' OR '1'='1" 
         for field, value in original.items()},
        
        # Command Injection
        {**original, field: f"{value}; ls -la" 
         for field, value in original.items()},
        
        # XXE (if XML)
        {**original, 'data': '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'},
        
        # CSRF token manipulation
        {**original, 'csrf_token': 'invalid'},
        
        # Parameter pollution
        {**original, 'role': 'admin', 'is_admin': 'true'},
    ]
    
    # 并行测试所有变体
    for test_case in test_cases:
        shadow_page = await shadow_browser.new_page()
        await shadow_page.goto(form_data['url'])
        await submit_form(shadow_page, test_case)
        await analyze_response(shadow_page)
```

### B. API端点自动发现与测试

```python
class ShadowAPIExplorer:
    """
    当用户访问任何页面时，Shadow Browser自动探索API
    """
    
    async def explore_apis(self, base_url, shadow_browser):
        """探索和测试API端点"""
        
        # 常见API路径
        api_paths = [
            '/api/', '/v1/', '/v2/', '/graphql',
            '/rest/', '/ajax/', '/json/', '/data/',
            '/admin/', '/user/', '/users/', '/profile/',
            '/config/', '/settings/', '/debug/', '/status/'
        ]
        
        # 常见API操作
        operations = [
            'list', 'get', 'create', 'update', 'delete',
            'search', 'filter', 'export', 'import',
            'upload', 'download', 'info', 'stats'
        ]
        
        # 生成可能的端点
        potential_endpoints = []
        for path in api_paths:
            for op in operations:
                potential_endpoints.extend([
                    f"{base_url}{path}{op}",
                    f"{base_url}{path}{op}s",
                    f"{base_url}{path}{op}/1",
                ])
        
        # 静默测试
        for endpoint in potential_endpoints:
            await self.test_endpoint(endpoint, shadow_browser)
    
    async def test_endpoint(self, endpoint, shadow_browser):
        """测试单个端点"""
        # 测试未授权访问
        response = await shadow_browser.request.get(endpoint)
        if response.status == 200:
            # 发现可访问端点，深度测试
            await self.deep_test_endpoint(endpoint, response)
```

### C. 智能IDOR探测

```python
class ShadowIDORHunter:
    """
    监测URL模式，自动进行IDOR测试
    """
    
    def __init__(self):
        self.url_patterns = {}  # 记录URL模式
        self.id_parameters = set()  # 识别的ID参数
        
    async def on_user_navigation(self, url):
        """用户导航时分析URL模式"""
        # 提取可能的ID
        ids = self.extract_ids(url)
        
        if ids:
            # 在Shadow Browser中测试相邻ID
            await self.test_adjacent_ids(url, ids)
    
    def extract_ids(self, url):
        """提取URL中的ID"""
        import re
        
        patterns = [
            r'/(\d+)(?:/|$)',  # /user/123/
            r'[?&]id=(\d+)',   # ?id=123
            r'[?&]user=(\d+)', # ?user=123
            r'[?&]uid=(\d+)',  # ?uid=123
            r'/[a-z]+/([a-f0-9-]{36})',  # UUID
        ]
        
        ids = []
        for pattern in patterns:
            matches = re.findall(pattern, url)
            ids.extend(matches)
        
        return ids
    
    async def test_adjacent_ids(self, url, original_ids):
        """测试相邻的ID"""
        for original_id in original_ids:
            if original_id.isdigit():
                # 数字ID：测试前后的值
                test_ids = [
                    int(original_id) - 1,
                    int(original_id) + 1,
                    int(original_id) + 10,
                    0, 1, 999999
                ]
            else:
                # 字符串ID：尝试常见值
                test_ids = ['admin', 'test', '1', '0']
            
            for test_id in test_ids:
                test_url = url.replace(str(original_id), str(test_id))
                await self.shadow_test_url(test_url)
```

## 6. 结果收集与报告

### A. 静默收集，智能聚合

```python
class SilentResultCollector:
    """
    静默收集所有测试结果，智能聚合和去重
    """
    
    def __init__(self):
        self.findings = []
        self.dedup_cache = set()
        
    async def collect(self, test_result):
        """收集测试结果"""
        # 生成指纹用于去重
        fingerprint = self.generate_fingerprint(test_result)
        
        if fingerprint not in self.dedup_cache:
            self.dedup_cache.add(fingerprint)
            
            # 评估严重性
            severity = self.assess_severity(test_result)
            
            # 静默记录
            self.findings.append({
                'timestamp': time.time(),
                'vulnerability': test_result['type'],
                'severity': severity,
                'evidence': test_result['evidence'],
                'shadow_test': True,  # 标记为shadow测试
                'user_action': test_result.get('triggered_by')
            })
    
    def generate_report(self):
        """生成报告（只在需要时）"""
        return {
            'total_tests': len(self.dedup_cache),
            'findings': self.findings,
            'critical': [f for f in self.findings if f['severity'] == 'critical'],
            'high': [f for f in self.findings if f['severity'] == 'high'],
            'medium': [f for f in self.findings if f['severity'] == 'medium'],
            'low': [f for f in self.findings if f['severity'] == 'low']
        }
```

## 7. 实现优先级

### Phase 1: 基础镜像（1周）
- 实现用户操作捕获
- 创建Shadow Browser池
- 基础操作镜像

### Phase 2: 智能变异（1周）
- 实现TestVariantGenerator
- 添加常见漏洞payload
- 智能调度系统

### Phase 3: 深度测试（2周）
- API自动探索
- IDOR智能检测
- 表单劫持测试

### Phase 4: 优化与调优（1周）
- 性能优化
- 去重算法
- 报告生成

## 8. 关键优势

✅ **完全用户无感**
- 所有测试在后台Shadow Browser进行
- 不影响用户正常浏览
- 无需用户配合

✅ **深度且全面**
- 每个用户操作触发数十个安全测试
- 自动探索未访问的功能点
- 智能关联测试

✅ **智能且高效**
- 利用用户空闲时间
- 并行测试提高效率
- 智能去重避免重复

✅ **上下文感知**
- 自动继承用户认证
- 理解应用逻辑
- 适应性测试策略

## 9. 示例场景

### 用户场景：
用户正常登录网站，浏览商品，添加购物车，完成支付。

### Shadow Browser 暗中进行：
1. **登录时**：测试SQL注入、密码爆破、认证绕过
2. **浏览商品时**：测试IDOR、API未授权、信息泄露
3. **添加购物车时**：测试价格篡改、数量溢出、CSRF
4. **支付时**：测试支付绕过、金额篡改、条件竞争

### 用户体验：
完全无感知，正常完成购物流程。

### 实际效果：
Shadow Browser已完成数百个安全测试，发现多个高危漏洞。

这就是真正的"用户无感"深度测试！
