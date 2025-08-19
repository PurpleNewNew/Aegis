# Passive模式工作流程图表

## 泳道图 (Swimlane Diagram)

```mermaid
graph TB
    subgraph "用户界面"
        UI[用户浏览器界面]
        UI_INTERACTION[用户交互操作]
    end
    
    subgraph "CDP控制器"
        CDP[CDP控制器]
        EVENT[事件监听器]
    end
    
    subgraph "调查管理器"
        IM[InvestigationManager]
        PASSIVE_HANDLER[被动模式处理器]
    end
    
    subgraph "交互工作器"
        IW[InteractionWorker]
        JS_ANALYZER[JS断点分析]
        NETWORK_ANALYZER[网络数据包分析]
        SHADOW_TESTER[影子浏览器测试]
    end
    
    subgraph "浏览器池"
        BP[BrowserPool]
        MAIN_BROWSER[主浏览器]
        SHADOW_BROWSER[影子浏览器]
    end
    
    subgraph "输出队列"
        OUTPUT[输出队列]
        REPORT[分析报告]
    end
    
    %% 流程连接
    UI --> CDP
    UI_INTERACTION --> EVENT
    EVENT --> IM
    IM --> PASSIVE_HANDLER
    PASSIVE_HANDLER --> IW
    IW --> BP
    BP --> MAIN_BROWSER
    
    %% 分析流程
    IW --> JS_ANALYZER
    IW --> NETWORK_ANALYZER
    IW --> SHADOW_TESTER
    SHADOW_TESTER --> SHADOW_BROWSER
    
    %% 输出流程
    JS_ANALYZER --> OUTPUT
    NETWORK_ANALYZER --> OUTPUT
    SHADOW_TESTER --> OUTPUT
    OUTPUT --> REPORT
    
    %% 样式定义
    classDef userStyle fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef controllerStyle fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    classDef managerStyle fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef workerStyle fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef browserStyle fill:#fce4ec,stroke:#880e4f,stroke-width:2px
    classDef outputStyle fill:#f1f8e9,stroke:#33691e,stroke-width:2px
    
    class UI,UI_INTERACTION userStyle
    class CDP,EVENT controllerStyle
    class IM,PASSIVE_HANDLER managerStyle
    class IW,JS_ANALYZER,NETWORK_ANALYZER,SHADOW_TESTER workerStyle
    class BP,MAIN_BROWSER,SHADOW_BROWSER browserStyle
    class OUTPUT,REPORT outputStyle
```

## 时序图 (Sequence Diagram)

```mermaid
sequenceDiagram
    participant User as 用户
    participant CDP as CDP控制器
    participant IM as InvestigationManager
    participant IW as InteractionWorker
    participant BP as BrowserPool
    participant MB as 主浏览器
    participant SB as 影子浏览器
    participant Output as 输出队列
    
    Note over User,Output: Passive模式启动阶段
    User->>CDP: 启动浏览器
    CDP->>IM: 初始化InvestigationManager
    IM->>IM: 检查execution_mode='passive'
    IM->>BP: 获取浏览器上下文
    BP-->>IM: 返回浏览器上下文
    IM->>MB: 导航到起始URL
    IM->>Output: 输出准备就绪报告
    
    Note over User,Output: 用户交互监听阶段
    loop 持续监听
        User->>MB: 进行页面交互(点击/输入/提交)
        MB->>CDP: 触发交互事件
        CDP->>IM: 发送user_interaction事件
        IM->>IM: 检查交互类型是否在监听列表
        alt 交互类型匹配
            IM->>IW: 启动analyze_interaction
            IW->>BP: 获取浏览器上下文
            BP-->>IW: 返回浏览器上下文
            
            Note over IW,MB: 创建交互快照
            IW->>MB: 注入认证状态
            IW->>MB: 导航到交互页面
            IW->>MB: 创建交互快照
            MB-->>IW: 返回快照数据
            
            Note over IW,MB: JS断点分析
            IW->>MB: 注入JS分析脚本
            IW->>MB: 收集事件监听器
            IW->>MB: 分析相关函数
            MB-->>IW: 返回JS分析结果
            
            Note over IW,MB: 网络数据包分析
            IW->>MB: 设置网络监听器
            IW->>MB: 模拟用户交互
            MB->>MB: 触发网络请求
            IW->>MB: 捕获请求/响应
            MB-->>IW: 返回网络数据包
            
            Note over IW,SB: 影子浏览器测试
            IW->>BP: 获取影子浏览器上下文
            BP-->>IW: 返回影子浏览器
            IW->>SB: 注入认证状态
            IW->>SB: 导航到目标页面
            
            par XSS测试
                IW->>SB: 执行XSS攻击载荷
                SB-->>IW: 返回XSS测试结果
            and 输入验证测试
                IW->>SB: 执行SQL注入等测试
                SB-->>IW: 返回输入验证结果
            and CSRF测试
                IW->>SB: 检查CSRF令牌
                SB-->>IW: 返回CSRF测试结果
            end
            
            IW->>BP: 释放影子浏览器
            
            Note over IW,Output: 生成分析报告
            IW->>IW: 汇总所有分析结果
            IW->>IW: 计算风险等级
            IW->>Output: 输出交互分析报告
            
        else 交互类型不匹配
            IM->>IM: 跳过分析
        end
    end
    
    Note over User,Output: 页面跳转处理
    User->>MB: 页面跳转/重新加载
    MB->>CDP: 触发导航事件
    CDP->>IM: 发送navigation事件
    IM->>IM: Passive模式下不进行侦察
    IM->>MB: 仅更新当前页面状态
```

## 组件说明

### 主要组件

1. **用户界面 (User Interface)**
   - 用户浏览器界面
   - 用户交互操作（点击、输入、提交）

2. **CDP控制器 (CDP Controller)**
   - 监听浏览器事件
   - 事件分发和处理

3. **调查管理器 (InvestigationManager)**
   - 被动模式处理器
   - 交互事件过滤和分发

4. **交互工作器 (InteractionWorker)**
   - JS断点分析器
   - 网络数据包分析器
   - 影子浏览器测试器

5. **浏览器池 (BrowserPool)**
   - 主浏览器（用户交互）
   - 影子浏览器（安全测试）

6. **输出队列 (Output Queue)**
   - 分析报告生成
   - 结果汇总和输出

### 工作流程特点

1. **被动监听**
   - 不主动进行页面侦察
   - 仅响应实际用户交互

2. **实时分析**
   - 用户交互后立即分析
   - 多维度安全检测

3. **隔离测试**
   - 影子浏览器独立测试
   - 不影响用户正常使用

4. **全面覆盖**
   - JS断点分析
   - 网络数据包分析
   - 多种安全测试