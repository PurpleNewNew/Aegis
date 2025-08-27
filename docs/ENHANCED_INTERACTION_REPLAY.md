# 被动模式完整交互复现功能说明

## 概述

Aegis 的被动模式现在支持完整的用户操作序列录制和复现，能够完美复现用户的复杂操作流程，包括登录、表单提交等多步骤操作。

## 核心改进

### 1. 完整的交互录制

#### 新增交互录制器 (`interaction_recorder.js`)
- **记录所有交互类型**：点击、输入、键盘、焦点、表单事件等
- **精确的时序记录**：记录每个操作的相对时间戳
- **完整的元素信息**：选择器、属性、值、状态等
- **页面状态快照**：URL、标题、DOM 状态等
- **操作上下文**：修饰键、坐标、输入类型等

#### 录制的数据结构
```javascript
{
    id: "unique_id",
    timestamp: 1234567890,
    relativeTime: 1500,  // 相对于录制开始的时间
    type: "input",       // 交互类型
    element: {
        selector: "body > form > input[type='text']",
        tagName: "input",
        attributes: { /* 所有属性 */ },
        value: "user_input",
        // ...
    },
    details: {
        inputType: "insertText",
        data: "a",  // 按下的字符
        // ...
    }
}
```

### 2. 智能的序列管理

#### 交互序列管理器 (`InteractionSequenceManager`)
- **依赖关系分析**：自动识别操作之间的依赖关系
- **拓扑排序**：确保操作按照正确的顺序执行
- **执行顺序优化**：基于依赖关系确定最优执行路径

#### 依赖关系规则
- `input` 依赖于同一元素的 `focus` 事件
- `submit` 依赖于表单内所有 `input` 操作
- `click` 可能依赖于相关元素的输入操作

### 3. 精确的复现机制

#### 交互复现器 (`InteractionReplayer`)
- **完整的操作支持**：点击、输入、键盘、焦点、提交等
- **真实的输入模拟**：逐字符输入，模拟真实打字速度
- **智能重试机制**：标准操作失败时尝试 JavaScript 方案
- **状态等待**：确保操作完成后再执行下一步

#### 输入复现增强
```python
# 不再使用固定值
await locator.fill("aegis_replay")  # 旧方式

# 完美复现用户输入
for char in value:
    await locator.press(char)
    await asyncio.sleep(0.05)  # 模拟输入间隔
```

### 4. 操作验证机制

#### 交互验证器 (`InteractionValidator`)
- **元素存在性检查**：确保操作目标存在
- **可交互性验证**：检查元素是否可见、可点击、可编辑
- **序列完整性检查**：验证整个序列是否可以安全执行

## 工作流程

### 1. 录制阶段
```
用户操作 → 交互录制器 → 记录完整序列 → 发送到后端
```

### 2. 分析阶段
```
接收序列 → 序列管理器分析依赖 → 生成执行顺序 → 验证可行性
```

### 3. 复现阶段
```
创建影子浏览器 → 注入认证状态 → 按序复现操作 → 捕获结果
```

## 关键特性

### 1. 完整的操作依赖支持
- **登录流程**：用户名输入 → 密码输入 → 验证码 → 点击登录
- **表单填写**：多个输入框按顺序填写
- **多步骤流程**：分步表单、向导式界面

### 2. 精确的时序控制
- **操作间隔**：保持用户原始操作节奏
- **异步等待**：等待页面响应和状态变化
- **网络请求**：等待 AJAX 请求完成

### 3. 错误处理和恢复
- **重试机制**：操作失败时自动重试
- **备选方案**：Playwright 失败时使用 JavaScript
- **状态恢复**：复现失败时恢复页面状态

### 4. 复杂场景支持
- **动态内容**：处理 AJAX 加载的内容
- **单页应用**：处理路由变化
- **框架兼容**：支持 React、Vue 等现代框架

## 使用示例

### 1. 登录流程复现
```javascript
// 用户操作序列
[
    {type: "focus", element: {selector: "#username"}},
    {type: "input", element: {selector: "#username", value: "testuser"}},
    {type: "focus", element: {selector: "#password"}},
    {type: "input", element: {selector: "#password", value: "testpass"}},
    {type: "click", element: {selector: "#login-button"}}
]

// 系统会自动：
// 1. 分析依赖关系
// 2. 按正确顺序复现
// 3. 捕获登录请求
// 4. 分析安全性
```

### 2. 表单提交流程
```javascript
// 包括验证码、复杂表单的完整流程
[
    {type: "input", element: {selector: "#email", value: "test@example.com"}},
    {type: "input", element: {selector: "#phone", value: "13800138000"}},
    {type: "input", element: {selector: "#captcha", value: "abcd"}},
    {type: "change", element: {selector: "#agreement", checked: true}},
    {type: "submit", element: {selector: "#registration-form"}}
]
```

## 配置选项

### 1. 录制配置
```yaml
passive_mode:
  # 启用增强录制
  enable_enhanced_recording: true
  
  # 录制选项
  recording_options:
    capture_screenshots: true    # 是否捕获截图
    record_network_requests: true # 记录网络请求
    max_sequence_length: 100      # 最大序列长度
```

### 2. 复现配置
```yaml
passive_mode:
  # 复现选项
  replay_options:
    wait_after_action: 0.3      # 操作后等待时间
    max_retries: 3              # 最大重试次数
    enable_javascript_fallback: true # 启用 JavaScript 备选方案
```

## 性能优化

### 1. 资源管理
- 按需创建影子浏览器
- 复用浏览器实例
- 及时清理资源

### 2. 智能调度
- 批量处理操作序列
- 避免频繁创建销毁
- 并行执行独立任务

### 3. 缓存机制
- 缓存页面状态
- 复用认证信息
- 避免重复加载

## 最佳实践

1. **确保录制完整**：等待页面完全加载后再开始操作
2. **合理设置等待时间**：根据页面响应速度调整等待时间
3. **处理动态内容**：对于 AJAX 加载的内容，适当增加等待时间
4. **验证复现结果**：检查复现是否成功，数据是否正确

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