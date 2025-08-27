# 被动模式交互复现功能演示

## 功能概述

Aegis的被动模式现在支持完整的用户操作序列录制和复现，能够完美复现用户的复杂操作流程，包括登录、表单提交等多步骤操作。

## 核心组件

### 1. 交互录制器 (interaction_recorder.js)
- **记录所有交互类型**：点击、输入、键盘、焦点、表单事件等
- **精确的时序记录**：记录每个操作的相对时间戳
- **完整的元素信息**：选择器、属性、值、状态等
- **页面状态快照**：URL、标题、DOM状态等
- **操作上下文**：修饰键、坐标、输入类型等

### 2. 交互序列管理器 (InteractionSequenceManager)
- **依赖关系分析**：自动识别操作之间的依赖关系
- **拓扑排序**：确保操作按照正确的顺序执行
- **执行顺序优化**：基于依赖关系确定最优执行路径

### 3. 交互复现器 (InteractionReplayer)
- **完整的操作支持**：点击、输入、键盘、焦点、提交等
- **真实的输入模拟**：逐字符输入，模拟真实打字速度
- **智能重试机制**：标准操作失败时尝试JavaScript方案
- **状态等待**：确保操作完成后再执行下一步

### 4. 交互验证器 (InteractionValidator)
- **元素存在性检查**：确保操作目标存在
- **可交互性验证**：检查元素是否可见、可点击、可编辑
- **序列完整性检查**：验证整个序列是否可以安全执行

## 工作流程

### 录制阶段
1. 用户访问网站并执行操作
2. 交互录制器自动记录所有操作
3. 每个操作包含完整的上下文信息
4. 操作序列实时发送到后端

### 分析阶段
1. 序列管理器分析操作间的依赖关系
2. 使用拓扑排序确定执行顺序
3. 验证器检查序列的可执行性
4. 生成优化的执行计划

### 复现阶段
1. 创建影子浏览器实例
2. 注入认证状态
3. 按序复现所有操作
4. 捕获网络请求和页面变化
5. 执行安全分析

## 使用示例

### 1. 登录流程复现
```javascript
// 用户操作序列（自动录制）
[
    {
        type: "focus",
        element: {selector: "#username"},
        timestamp: 1640995200000
    },
    {
        type: "input",
        element: {selector: "#username", value: "testuser"},
        details: {inputType: "insertText", data: "testuser"},
        timestamp: 1640995200100
    },
    {
        type: "focus",
        element: {selector: "#password"},
        timestamp: 1640995200300
    },
    {
        type: "input",
        element: {selector: "#password", value: "testpass123"},
        details: {inputType: "insertText", data: "testpass123"},
        timestamp: 1640995200400
    },
    {
        type: "click",
        element: {selector: "#login-button"},
        details: {triggers_network_request: true},
        timestamp: 1640995200500
    }
]

// 系统自动处理：
// 1. 分析依赖关系
// 2. 按正确顺序复现
// 3. 捕获登录请求
// 4. 分析安全性
```

### 2. 复杂表单填写
```javascript
// 包含验证码、多步骤的表单
[
    {type: "input", element: {selector: "#email", value: "test@example.com"}},
    {type: "input", element: {selector: "#phone", value: "13800138000"}},
    {type: "input", element: {selector: "#captcha", value: "abcd"}},
    {type: "change", element: {selector: "#agreement", checked: true}},
    {type: "submit", element: {selector: "#registration-form"}}
]
```

## 关键特性

### 1. 完整的操作依赖支持
- **登录流程**：用户名输入 → 密码输入 → 验证码 → 点击登录
- **表单填写**：多个输入框按顺序填写
- **多步骤流程**：分步表单、向导式界面

### 2. 精确的时序控制
- **操作间隔**：保持用户原始操作节奏
- **异步等待**：等待页面响应和状态变化
- **网络请求**：等待AJAX请求完成

### 3. 错误处理和恢复
- **重试机制**：操作失败时自动重试
- **备选方案**：Playwright失败时使用JavaScript
- **状态恢复**：复现失败时恢复页面状态

### 4. 复杂场景支持
- **动态内容**：处理AJAX加载的内容
- **单页应用**：处理路由变化
- **框架兼容**：支持React、Vue等现代框架

## 配置选项

### 在 config.yaml 中配置
```yaml
investigation_manager:
  execution_mode: 'passive'  # 设置为被动模式
  passive_mode:
    # 启用交互监控
    enable_interaction_monitoring: true
    # 分析深度
    analysis_depth: 'deep'
    # 自动安全测试
    auto_security_testing: true
    # 监控的交互类型
    interaction_types: ['click', 'submit', 'input']
    # 分析超时
    analysis_timeout: 360
    # 生成报告
    generate_interaction_reports: true
```

## 实际效果

### 修复前的问题
- ❌ 只能记录单个交互，无法处理操作序列
- ❌ 使用固定值复现输入，无法反映真实操作
- ❌ 无法处理操作间的依赖关系
- ❌ 对于"需要先A后B"的场景无法处理

### 修复后的改进
- ✅ **完整的操作序列**：记录并复现完整的操作流程
- ✅ **精确的时序控制**：保持操作的原始顺序和时间间隔
- ✅ **智能依赖分析**：自动识别操作间的依赖关系
- ✅ **完美输入复现**：逐字符复现用户的真实输入
- ✅ **错误处理和恢复**：多重重试机制和备选方案
- ✅ **复杂场景支持**：支持登录、表单、多步骤流程等

## 运行测试

验证功能是否正常工作：

```bash
# 运行所有测试
python run_tests.py

# 或直接运行被动模式测试
python tests/passive_mode/test_passive_mode_interaction.py

# 预期输出
# ✅ 交互录制器：记录所有类型的用户操作
# ✅ 序列管理器：分析操作依赖关系
# ✅ 交互复现器：精确复现操作序列
# ✅ 验证机制：确保操作可以安全执行
# ✅ 集成完成：所有组件已正确集成到系统中
```

## 注意事项

1. **网站兼容性**：某些网站可能有反自动化措施
2. **时间敏感操作**：某些操作可能对时序要求极高
3. **资源消耗**：完整的交互复理会消耗更多资源
4. **调试复杂度**：序列复现的问题可能比单步操作更难调试

## 未来改进

1. **视觉匹配**：当选择器失效时，使用图像识别定位元素
2. **智能等待**：基于页面特征自动确定等待时间
3. **异常恢复**：更强大的错误恢复和继续执行能力
4. **性能优化**：减少资源占用，提高执行效率