# Autonomous模式工作流程图

## 泳道图 (Swimlane Diagram)

```mermaid
graph TB
    subgraph 用户界面
        A1[启动调查] --> A2[设置目标URL]
        A2 --> A3[配置调查参数]
        A3 --> A4[开始自主调查]
        A4 --> A5[监控调查进度]
        A5 --> A6[查看最终报告]
    end
    
    subgraph 调查管理器
        B1[接收调查请求] --> B2[创建AgentWorker]
        B2 --> B3[分配浏览器资源]
        B3 --> B4[启动自主模式]
        B4 --> B5[监控执行状态]
        B5 --> B6[收集最终报告]
        B6 --> B7[输出到队列]
    end
    
    subgraph AgentWorker
        C1[初始化环境] --> C2[身份注入]
        C2 --> C3[初始导航侦察]
        C3 --> C4[构建观察内容]
        C4 --> C5[调用LLM决策]
        C5 --> C6[执行工具操作]
        C6 --> C7[更新侦察快照]
        C7 --> C8{达到最大步骤?}
        C8 -->|否| C4
        C8 -->|是| C9[生成最终报告]
        C9 --> C10[输出报告]
    end
    
    subgraph 浏览器池
        D1[分配浏览器上下文] --> D2[创建新页面]
        D2 --> D3[执行导航操作]
        D3 --> D4[执行交互操作]
        D4 --> D5[捕获页面内容]
        D5 --> D6[释放资源]
    end
    
    subgraph 分析工具
        E1[静态分析SAST] --> E2[秘密扫描]
        E2 --> E3[XSS漏洞检测]
        E3 --> E4[加密模式检测]
        E4 --> E5[网络请求分析]
    end
    
    subgraph 输出队列
        F1[接收报告数据] --> F2[格式化输出]
        F2 --> F3[存储报告文件]
        F3 --> F4[通知用户]
    end
    
    %% 连接关系
    A1 --> B1
    A2 --> B2
    A3 --> B3
    A4 --> B4
    B5 --> A5
    B6 --> F1
    B7 --> F2
    
    B2 --> C1
    B3 --> D1
    B4 --> C2
    
    C2 --> D2
    C3 --> D3
    C4 --> E1
    C5 --> C6
    C6 --> D4
    C6 --> E5
    C7 --> D5
    C9 --> F1
    C10 --> B6
    
    D3 --> E1
    D5 --> E1
    
    classDef userInterface fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef investigationManager fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    classDef agentWorker fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px
    classDef browserPool fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef analysisTools fill:#fce4ec,stroke:#880e4f,stroke-width:2px
    classDef outputQueue fill:#e0f2f1,stroke:#004d40,stroke-width:2px
    
    class A1,A2,A3,A4,A5,A6 userInterface
    class B1,B2,B3,B4,B5,B6,B7 investigationManager
    class C1,C2,C3,C4,C5,C6,C7,C8,C9,C10 agentWorker
    class D1,D2,D3,D4,D5,D6 browserPool
    class E1,E2,E3,E4,E5 analysisTools
    class F1,F2,F3,F4 outputQueue
```

## 时序图 (Sequence Diagram)

```mermaid
sequenceDiagram
    participant User as 用户
    participant IM as 调查管理器
    participant AW as AgentWorker
    participant BP as 浏览器池
    participant MP as 主页面
    participant P1 as 并行实例1
    participant P2 as 并行实例2
    participant P3 as 并行实例3
    participant Tools as 分析工具
    participant LLM as AI决策引擎
    participant Queue as 输出队列
    
    %% 1. 启动阶段
    User->>IM: 请求启动自主调查
    IM->>IM: 创建AgentWorker实例
    IM->>AW: 启动自主模式
    
    %% 2. 初始化阶段
    AW->>BP: 请求主浏览器上下文
    BP-->>AW: 分配主浏览器上下文
    AW->>MP: 创建主页面
    AW->>MP: 身份注入(如有)
    
    %% 3. 并行实例初始化
    Note over AW: 获取并行浏览器实例
    AW->>BP: 请求并行浏览器上下文1
    BP-->>AW: 分配并行实例1
    AW->>BP: 请求并行浏览器上下文2
    BP-->>AW: 分配并行实例2
    AW->>BP: 请求并行浏览器上下文3
    BP-->>AW: 分配并行实例3
    
    %% 4. 初始侦察阶段
    AW->>MP: 导航到目标URL
    MP-->>AW: 返回导航观察
    AW->>MP: 获取页面内容
    MP-->>AW: 返回HTML内容
    AW->>MP: 获取交互元素
    MP-->>AW: 返回交互元素列表
    
    %% 5. 静态分析
    AW->>Tools: 执行SAST分析
    Tools->>Tools: 秘密扫描
    Tools->>Tools: XSS漏洞检测
    Tools->>Tools: 加密模式检测
    Tools-->>AW: 返回SAST结果
    
    %% 6. 构建侦察快照
    AW->>AW: 构建侦察快照
    Note over AW: 包含页面内容摘要、交互元素、SAST结果
    
    %% 7. 自主决策循环
    loop 最大步骤次数
        %% 7.1 思考决策
        AW->>AW: 构建当前观察内容
        AW->>LLM: 发送决策请求
        LLM-->>AW: 返回AI决策(思考+工具调用)
        
        %% 7.2 并行执行行动
        alt 有效工具调用
            par 并行操作执行
                AW->>MP: 执行工具操作
                MP-->>AW: 返回操作结果
            and 并行实例1操作
                AW->>P1: 执行相同操作
                P1-->>AW: 返回操作结果
            and 并行实例2操作
                AW->>P2: 执行相同操作
                P2-->>AW: 返回操作结果
            and 并行实例3操作
                AW->>P3: 执行相同操作
                P3-->>AW: 返回操作结果
            end
            
            Note over AW: 合并并行结果
            AW->>AW: 合并主页面和并行实例结果
            
            %% 7.3 页面跳转检测
            alt 检测到页面跳转
                AW->>AW: 检查URL是否已访问
                alt 新URL
                    AW->>AW: 标记需要侦察
                else 已访问URL
                    AW->>MP: 获取页面内容
                    MP-->>AW: 返回HTML内容
                    AW->>AW: 计算内容哈希
                    alt 内容有变化
                        AW->>AW: 标记需要侦察
                    else 内容未变化
                        AW->>AW: 跳过重复侦察
                    end
                end
                alt 需要侦察
                    AW->>MP: 获取新交互元素
                    MP-->>AW: 返回新交互元素列表
                    AW->>Tools: 重新执行SAST分析
                    Tools-->>AW: 返回新SAST结果
                    AW->>AW: 更新侦察快照
                end
            end
            
            %% 7.4 记录发现
            alt 发现安全问题
                AW->>AW: 添加到final_findings
            end
        else
            AW->>AW: 记录无效决策
        end
        
        %% 7.5 终止条件检查
        alt 达到终止条件
            AW->>AW: 退出决策循环
        end
    end
    
    %% 8. 报告生成阶段
    AW->>AW: 生成架构指纹
    AW->>AW: 构建最终报告数据
    AW->>Queue: 输出报告到队列
    Queue-->>AW: 确认接收
    
    %% 9. 清理阶段
    Note over AW: 释放所有浏览器资源
    AW->>BP: 释放主浏览器上下文
    BP-->>AW: 确认释放
    AW->>BP: 释放并行浏览器上下文1
    BP-->>AW: 确认释放
    AW->>BP: 释放并行浏览器上下文2
    BP-->>AW: 确认释放
    AW->>BP: 释放并行浏览器上下文3
    BP-->>AW: 确认释放
    
    AW->>IM: 通知任务完成
    IM->>User: 通知调查完成
    IM->>Queue: 获取报告数据
    Queue-->>IM: 返回报告数据
    IM->>User: 展示最终报告
```

## 组件说明

### 1. 用户界面 (User Interface)
- **职责**: 提供用户交互界面，接收调查请求和配置参数
- **关键功能**: 启动调查、设置目标、监控进度、查看报告

### 2. 调查管理器 (Investigation Manager)
- **职责**: 管理调查任务的生命周期，协调各个Worker
- **关键功能**: 创建AgentWorker、分配资源、监控执行、收集报告

### 3. AgentWorker
- **职责**: 执行自主调查的核心逻辑，实现AI驱动的安全测试
- **关键功能**: 
  - 环境初始化和身份注入
  - 初始侦察和快照构建
  - LLM决策调用和工具执行
  - 页面跳转检测和侦察更新
  - 最终报告生成

### 4. 浏览器池 (Browser Pool)
- **职责**: 管理浏览器资源，提供页面操作能力
- **关键功能**: 分配/释放浏览器上下文、创建页面、执行操作

### 5. 分析工具 (Analysis Tools)
- **职责**: 提供各种安全分析能力
- **关键功能**: 
  - SAST静态分析(秘密扫描、XSS检测、加密模式检测)
  - 网络请求分析

### 6. 输出队列 (Output Queue)
- **职责**: 处理报告输出和存储
- **关键功能**: 接收报告数据、格式化输出、存储文件

## 工作流程特点

### 1. 自主决策
- AgentWorker通过LLM进行自主决策，无需人工干预
- 基于当前观察和历史记录做出智能判断
- 支持多种工具操作的自动执行

### 2. 持续侦察
- 在页面跳转时自动重新进行侦察
- 动态更新侦察快照，保持信息最新
- 支持多步骤深度调查

### 3. 智能分析
- 结合SAST和动态分析技术
- AI驱动的漏洞识别和风险评估
- 自动生成结构化安全报告

### 4. 智能重复检测
- **URL历史记录机制**: 系统维护已访问URL集合(`visited_urls`)，避免重复侦察相同页面
- **页面内容哈希比对**: 使用`url_content_hashes`字典存储页面内容哈希值，仅当页面内容发生变化时才重新侦察
- **页面刷新时跳过重复侦察**: 检测到页面刷新时，如果URL和内容哈希都未变化，则跳过重复侦察
- **提升调查效率**: 显著减少不必要的重复侦察，提升运行效率并优化资源消耗

### 5. 并行处理优化
- **Autonomous模式并行测试**: 可同时获取最多3个浏览器上下文(受浏览器池大小限制)，并行测试多个功能点
- **主页面与并行实例协同**: 主页面(`main_page`)负责主要侦察决策，并行实例执行相同操作并收集结果
- **任务结果合并**: 并行任务完成后，结果合并到历史记录(`history`)中，确保数据完整性
- **Passive模式并行交互**: 为每个用户交互事件分配独立的影子浏览器实例，支持同时分析多个交互点
- **交互任务管理**: 使用`active_interaction_tasks`字典跟踪进行中的交互分析任务，避免资源冲突
- **智能任务调度**: 当并行任务数超过限制时，等待最早任务完成后再处理新任务，确保系统稳定性

### 6. 资源管理
- **浏览器池管理**: 支持多个浏览器实例并行工作，提高资源利用率
- **认证状态同步**: 在并行实例间保持认证状态一致性
- **内存优化**: 及时释放不再需要的浏览器上下文，避免内存泄漏

### 7. 完整生命周期
- **初始化阶段**: 配置调查参数，获取浏览器上下文，进行初始侦察
- **调查循环**: AI决策 → 工具调用 → 结果分析 → 页面跳转检测 → 重新侦察
- **结束阶段**: 生成调查报告，释放资源，输出最终结果

## Passive模式并行处理时序图

```mermaid
sequenceDiagram
    participant U as User
    participant IW as InteractionWorker
    participant BP as BrowserPool
    participant B1 as BrowserInstance1
    participant B2 as BrowserInstance2
    participant B3 as BrowserInstance3
    participant AT as AnalysisTools
    participant R as Reporter
    
    Note over IW: Passive模式并行交互分析初始化
    IW->>IW: 初始化并行任务管理器
    Note over IW: max_parallel_interactions=3<br/>active_interaction_tasks={}<br/>interaction_history=[]
    
    Note over U: 用户连续点击多个功能点
    U->>IW: 交互事件1(点击功能A)
    Note over IW: 生成唯一交互ID1
    IW->>IW: 检查ID1是否在活动任务中
    IW->>BP: 获取浏览器上下文1
    BP-->>IW: 返回浏览器实例1
    
    par 并行分析任务1
        IW->>B1: 注入认证状态
        B1-->>IW: 认证完成
        IW->>B1: 导航到交互页面
        B1-->>IW: 页面加载完成
        IW->>B1: 创建交互快照
        B1-->>IW: 返回快照数据
        IW->>AT: 执行针对性安全分析
        AT-->>IW: 返回分析结果
        IW->>R: 生成交互报告
        R-->>IW: 报告生成完成
        IW->>IW: 记录到交互历史
        IW->>BP: 释放浏览器实例1
        BP-->>IW: 释放完成
    end
    
    Note over IW: 任务1完成回调
    IW->>IW: 从活动任务中移除ID1
    
    U->>IW: 交互事件2(点击功能B)
    Note over IW: 生成唯一交互ID2
    IW->>IW: 检查ID2是否在活动任务中
    IW->>BP: 获取浏览器上下文2
    BP-->>IW: 返回浏览器实例2
    
    par 并行分析任务2
        IW->>B2: 注入认证状态
        B2-->>IW: 认证完成
        IW->>B2: 导航到交互页面
        B2-->>IW: 页面加载完成
        IW->>B2: 创建交互快照
        B2-->>IW: 返回快照数据
        IW->>AT: 执行针对性安全分析
        AT-->>IW: 返回分析结果
        IW->>R: 生成交互报告
        R-->>IW: 报告生成完成
        IW->>IW: 记录到交互历史
        IW->>BP: 释放浏览器实例2
        BP-->>IW: 释放完成
    end
    
    Note over IW: 任务2完成回调
    IW->>IW: 从活动任务中移除ID2
    
    U->>IW: 交互事件3(点击功能C)
    Note over IW: 生成唯一交互ID3
    IW->>IW: 检查ID3是否在活动任务中
    IW->>BP: 获取浏览器上下文3
    BP-->>IW: 返回浏览器实例3
    
    par 并行分析任务3
        IW->>B3: 注入认证状态
        B3-->>IW: 认证完成
        IW->>B3: 导航到交互页面
        B3-->>IW: 页面加载完成
        IW->>B3: 创建交互快照
        B3-->>IW: 返回快照数据
        IW->>AT: 执行针对性安全分析
        AT-->>IW: 返回分析结果
        IW->>R: 生成交互报告
        R-->>IW: 报告生成完成
        IW->>IW: 记录到交互历史
        IW->>BP: 释放浏览器实例3
        BP-->>IW: 释放完成
    end
    
    Note over IW: 任务3完成回调
    IW->>IW: 从活动任务中移除ID3
    
    Note over U: 用户点击第4个功能点(超出限制)
    U->>IW: 交互事件4(点击功能D)
    Note over IW: 生成唯一交互ID4<br/>检查活动任务数=3(达到限制)
    IW->>IW: 等待最早任务完成
    
    Note over IW: 智能任务调度
    IW->>IW: 监控活动任务状态
    Note over IW: 任务1完成，释放资源
    IW->>BP: 获取浏览器上下文1(复用)
    BP-->>IW: 返回浏览器实例1
    
    par 并行分析任务4
        IW->>B1: 注入认证状态
        B1-->>IW: 认证完成
        IW->>B1: 导航到交互页面
        B1-->>IW: 页面加载完成
        IW->>B1: 创建交互快照
        B1-->>IW: 返回快照数据
        IW->>AT: 执行针对性安全分析
        AT-->>IW: 返回分析结果
        IW->>R: 生成交互报告
        R-->>IW: 报告生成完成
        IW->>IW: 记录到交互历史
        IW->>BP: 释放浏览器实例1
        BP-->>IW: 释放完成
    end
    
    Note over IW: 任务4完成回调
    IW->>IW: 从活动任务中移除ID4
    
    Note over IW: Passive模式并行处理总结
    IW->>IW: 输出交互历史统计<br/>成功分析: 4个交互点<br/>并行处理: 最多3个同时进行<br/>资源利用: 3个浏览器实例充分利用
```

## 与Passive模式的对比

| 特性 | Autonomous模式 | Passive模式 |
|------|---------------|-------------|
| 决策方式 | AI自主决策 | 等待用户交互 |
| 侦察时机 | 启动时+页面跳转时 | 仅用户交互后 |
| 分析深度 | 多步骤深度调查 | 单次交互分析 |
| 适用场景 | 全面安全审计 | 实时交互监控 |
| 资源消耗 | 较高 | 较低 |
| 响应速度 | 较慢 | 实时 |