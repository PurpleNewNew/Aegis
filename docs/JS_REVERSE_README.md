# JS逆向功能使用说明

## 概述

Aegis的JS逆向功能是一个专门用于分析和理解前端JavaScript加密逻辑的工具。它结合了Chrome DevTools Protocol(CDP)和AI分析，能够：

1. **实时捕获**JavaScript执行上下文
2. **智能分析**加密算法和密钥管理
3. **关联网络请求**与JS执行过程
4. **提供详细**的逆向分析报告

## 核心组件

### 1. 统一钩子 (unified_hooks.js)
合并了IAST和JS逆向功能的统一钩子脚本，用于捕获：
- 加密/解密函数调用 (encrypt, decrypt, sign, verify)
- 数据编码/解码 (btoa, atob, encodeURIComponent)
- 网络请求 (XHR, Fetch)
- Web Crypto API调用
- 其他关键执行点

### 2. CDP JS逆向调试器 (cdp_js_reverse_debugger.py)
增强的CDP调试器，提供：
- 智能断点设置
- 完整的调用栈捕获
- 变量状态提取
- 代码片段获取
- 会话管理

### 3. JS逆向分析器 (js_reverse_worker.py)
核心分析引擎，负责：
- 处理调试事件
- 关联多源数据
- 调用AI进行分析
- 缓存分析结果
- 生成结构化报告

### 4. 加密分析工具 (crypto_analyzer.py)
静态分析工具，能够：
- 识别加密算法模式
- 检测硬编码密钥
- 发现安全弱点
- 提供修复建议

## 使用方法

### 1. 启动Chrome浏览器
```bash
# Windows
"C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222

# macOS
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --remote-debugging-port=9222

# Linux
google-chrome --remote-debugging-port=9222
```

### 2. 配置目标域名
编辑 `config.yaml` 文件，在 `whitelist_domains` 中添加要分析的域名：
```yaml
scanner_scope:
  whitelist_domains: ["example.com", "test.com"]
```

### 3. 配置LLM服务
确保 `config.yaml` 中的LLM配置正确：
```yaml
llm_service:
  reasoning_level: 'high'  # 推理级别：high/medium/low
  api_config:
    base_url: "http://localhost:1234/v1"  # LM Studio或Ollama地址
    model_name: "openai/gpt-oss-20b"
    api_key: "lm-studio"
    timeout: 300
```

### 4. 运行JS逆向分析工具
```bash
python js_reverse_demo.py
```

### 5. 使用方法
1. 在Chrome中访问配置的网站
2. 执行可能触发加密的操作（如点击登录、提交表单）
3. 观察控制台输出的AI分析结果

## 分析示例

### 输入数据
- JavaScript代码片段（包含加密逻辑）
- 执行时的变量状态
- 相关的网络请求
- JS钩子捕获的事件

### AI分析输出
```
--- JS逆向分析结果 ---
URL: https://example.com/login
触发函数: handleLogin

AI分析:
这段代码实现了AES-CBC加密算法...
[详细分析过程]

结构化结果:
{
  "algorithms": ["AES-CBC"],
  "key_management": "server_fetched",
  "security_mechanisms": ["timestamp", "nonce"],
  "key_source": "通过API /api/getKey获取",
  "process_summary": "1. 获取服务器密钥...",
  "vulnerabilities": ["predictable_nonce"]
}
-----------------------
```

## 功能特点

### 1. 多维度数据关联
- **调试事件**: CDP断点捕获的执行上下文
- **JS钩子事件**: 函数调用和返回值
- **网络数据**: 相关的API请求和响应
- **时间线**: 事件发生的时序关系

### 2. 智能缓存机制
- 避免重复分析相同代码
- 提高响应速度
- 减少LLM调用成本

### 3. 安全弱点检测
自动识别常见的安全问题：
- 硬编码密钥
- 固定IV
- 弱加密算法
- 可预测的Nonce
- 缺少安全机制

### 4. 静态+动态分析
- **静态分析**: 代码模式识别
- **动态分析**: 运行时状态捕获
- **AI增强**: 智能推理和理解

## 高级配置

### 1. 调整分析深度
在 `config.yaml` 中修改LLM的推理级别：
```yaml
llm_service:
  reasoning_level: 'high'  # high/medium/low
```

### 2. 自定义钩子
可以修改 `unified_hooks.js` 添加更多的监控点。

### 3. 扩展加密模式
在 `crypto_analyzer.py` 中添加新的算法模式。

## 注意事项

1. **只对授权的网站进行测试**
2. 确保Chrome浏览器已正确启动远程调试
3. LLM服务需要支持较长的上下文窗口
4. 分析结果仅供参考，需要人工验证

## 输出文件

- **AI对话记录**: `./logs/ai_dialogues.jsonl`
- 控制台实时输出分析结果