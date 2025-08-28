# Aegis: 混合智能与动态调试安全代理

Aegis是一个高度实验性的、前沿的Web安全审计框架。它将自主AI代理（Agent）与多种安全测试技术（SAST, DAST, IAST, Debugging）深度融合，构建了一个能够对现代Web应用进行深度、智能、自动化安全审计的终极系统。

<b>同志们！！这个玩意，目前就是个玩具，高度理想化，远超我的编码能力，充斥着大量AI生成的代码！！！生产使用打咩！但是如果有劳各位师傅们能贡献代码，我们可以一起把这个小玩具做大做强，变成大玩具甚至真正可用！</b>

## 核心设计思想

Aegis的最终形态，由三大核心理念驱动，旨在最大限度地模仿一位顶尖安全专家的思维与工作流：

1.  **“影子调查员” (无感的主动代理)**: Aegis在后台的“影子浏览器”中，对用户访问过的页面发起主动的、探索性的安全调查，而完全不干扰用户的正常浏览。它提供了被动式扫描的无感体验，但具备主动式测试的强大能力。

2.  **“AI指挥官 + 多维情报源” (混合智能)**: Aegis不单纯依赖LLM的通用推理。它为“AI指挥官”(`AgentWorker`)配备了三大多维度的情报来源：
    *   **静态分析(SAST)**: 框架集成了多种静态分析能力（例如 `src/utils/crypto_analyzer.py`），用于在分析过程中发现代码和资源中的静态线索（如密钥、危险函数）。
    *   **动态分析(DAST)**: `browser_tools`和`network_tools`是AI的“双手”，使其能与网站进行动态交互（点击、输入）和精确的发包测试。
    *   **运行时调试(Debugging)**: `UnifiedCDPDebugger`是AI的“窃听器”，通过在关键事件（如`click`）上设置断点，它能捕获到事件发生瞬间的JS运行时状态（如变量值），为AI提供无与伦比的“铁证”。

3.  **“双记忆系统” (可持续学习)**: 为了解决长期运行和上下文窗口限制的矛盾，Aegis为AI代理设计了双记忆系统：
    *   **长期记忆 (RAG)**: 基于ChromaDB，允许AI从过去相似架构的网站分析中学习经验。
    *   **工作记忆 (Summarization)**: AI在执行多步任务时，会通过LLM调用进行“自我总结”，将冗长的历史记录浓缩成简短的“状态摘要”，以防止上下文窗口溢出。

## 技术栈

- **核心框架**: Python, asyncio
- **浏览器自动化**: Playwright
- **AI模型调用**: OpenAI 兼容 API（如 LM Studio / Ollama / OpenAI）
- **HTTP客户端**: httpx
- **静态分析**: 内置的Python脚本
- **长期记忆**: ChromaDB

## 工作原理

Aegis的核心是双模驱动架构，不同模式下，各组件的协同方式不同。

### 被动模式 (Passive Mode) 工作流

在被动模式下，框架的核心是**无感地监听和分析用户产生的交互**。其职责被清晰地划分为“交互分析”和“会话保持”，由两个不同的Worker协同完成，以达到最高效率。

```mermaid
graph TD
    subgraph "用户侧 (User Side)"
        direction LR
        User["👤 用户"] -- "1. 正常操作" --> MainBrowser["🌐 主浏览器"]
        MainBrowser -- "2. 交互事件" --> CDPController["CDP 控制器"]
        CDPController -- "3. 事件入队" --> InteractionQueue["交互事件队列"]
    end

    subgraph "调度与分析 (Manager & Analysis)"
        direction TB
        InvestigationManager["🕵️ 调查任务管理器"] -- "4. 读取交互" --> InteractionQueue
        InvestigationManager -- "5. 聚合后派发分析任务" --> InteractionWorker["👩‍🔬 交互分析器"]
        InteractionWorker -- "6. 获取已登录的浏览器" --> BrowserPool["🕶️ 浏览器池"]
        InteractionWorker -- "7. 在后台重放并分析" --> AnalysisLoop{"分析循环"}
        AnalysisLoop -- "8. 输出报告" --> Reporter["📋 报告生成"]
    end

    subgraph "会话保持 (Session Holder)"
        direction TB
        AgentWorker_Passive["🤖 AgentWorker<br>(会话保持模式)"] -- "a. 登录并准备好环境" --> BrowserPool
        InvestigationManager -- "b. (可选)启动会话保持" --> AgentWorker_Passive
    end

    classDef user fill:#E8F8F5,stroke:#16A085,stroke-width:2px
    classDef manager fill:#FEF9E7,stroke:#F1C40F,stroke-width:2px
    class User, MainBrowser, CDPController, InteractionQueue user
    class InvestigationManager, InteractionWorker, BrowserPool, AnalysisLoop, Reporter, AgentWorker_Passive manager
```

### 主动模式 (Autonomous Mode) 工作流

在主动模式下，`AgentWorker` 成为绝对核心，作为一个自主代理，在目标网站上执行“观察-思考-行动”的循环，主动探索和攻击。

```mermaid
graph TD
    subgraph 启动 (Initiation)
        direction LR
        InvestigationManager[🕵️ 调查任务管理器] -- 1. 分配任务和目标URL --> AgentWorker_Active(🤖 AgentWorker)
    end

    subgraph "AI代理的“思考-行动”循环"
        direction TB
        AgentWorker_Active -- 2. 获取浏览器 --> BrowserPool[(🕶️ 浏览器池)]
        AgentWorker_Active -- 3. 观察 (Observe) --> Page(页面状态)
        Page -- 4. 形成上下文 --> AgentWorker_Active
        AgentWorker_Active -- 5. 思考 (Think) --> LLM[(LLM 决策)]
        LLM -- 6. 返回工具调用 --> AgentWorker_Active
        AgentWorker_Active -- 7. 行动 (Act) --> Tools(🛠️ 执行工具<br>如: browser_tools, scanners)
        Tools -- 8. 更新页面状态 --> Page
        subgraph "持续情报"
            Debugger(CDP 调试器) -- IAST事件 --> AgentWorker_Active
        end
    end

    AgentWorker_Active -- 9. 结束并报告 --> Reporter(📋 报告生成)

    classDef manager fill:#FEF9E7,stroke:#F1C40F,stroke-width:2px
    classDef agent fill:#E8F8F5,stroke:#16A085,stroke-width:2px
    class InvestigationManager, BrowserPool, Reporter manager
    class AgentWorker_Active, Page, LLM, Tools, Debugger agent
```

## 安装与使用
### 前置要求
- Python 3.10+
- Chrome/Chromium 浏览器
- 支持的LLM服务 (本地 LM Studio / Ollama / 其他 OpenAI 兼容 API 服务)

1.  **安装依赖**: 
    确保您的系统已安装Python 3.10+。然后运行：
    ```bash
    pip install -r requirements.txt
    ```

2.  **启动Chrome浏览器**: 
    Aegis需要连接到一个开启了远程调试端口的Chrome实例。请先关闭所有Chrome进程，然后使用您的系统对应的命令启动它：
    ```bash
    # Windows
    "C:\Program Files\Google\Chrome\Application\chrome.exe" --remote-debugging-port=9222

    # macOS
    /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --remote-debugging-port=9222

    # Linux
    google-chrome --remote-debugging-port=9222
    ```

3.  **配置Aegis**: 
    打开 `config.yaml` 文件进行配置。
    - **`whitelist_domains`**: **（重要）** 将您要测试的域名或IP地址加入白名单。
    - **`browser_pool`**: 
        - **`mode`**: 选择浏览器池模式
            - `shared`: 共享主浏览器的认证状态（推荐）
            - `standalone`: 独立浏览器但复制认证
        - `pool_size`: 并发扫描数量
    - **`llm_service`**:
        - 使用与 OpenAI 兼容的 API 服务（如本地 LM Studio / Ollama 的 openai 兼容模式）。
        - 在 `api_config` 中配置 `base_url`、`model_name`、`api_key` 与 `timeout`。

4.  **运行Aegis**: 
    ```bash
    playwright install
    python main.py
    ```
    程序启动后，您只需在主浏览器中正常浏览网页。Aegis的“侦察兵”会监控您的导航，并自动派遣“AI指挥官”在后台对您访问的页面进行自主的、混合式的安全审计。所有AI的思考过程和决策都会实时打印在Aegis的终端中。

5.  **登录目标网站**: 
    - 在Chrome中正常登录您要测试的网站
    - 完成任何需要的人工验证（如验证码）
    - Aegis会自动同步认证状态到影子浏览器

6.  **查看结果**: 
    - **实时对话**: 在Aegis运行的终端中，可以直接看到AI的思考和决策过程。
    - **最终报告**: 在`./reports`目录下，会为每个目标生成一份详细的Markdown格式审计报告。
    - **AI对话存档**: 在`./logs`目录下，`ai_dialogues.jsonl`文件会完整记录每一次与AI的对话。

## 文档

详细的技术文档请参考 [docs/](./docs/) 目录，包含：

### 📖 核心功能文档
- 被动模式交互复现功能说明
- 被动扫描模式修复总结
- 影子浏览器并行测试功能
- JS逆向功能使用说明

### 📐 架构设计文档
- 系统架构图和组件说明
- 自主模式/被动模式架构设计
- CDP与网络AI集成架构

## 测试

### 运行被动模式交互复现测试
```bash
# 运行所有测试
python run_tests.py

# 或直接运行被动模式测试
python tests/passive_mode/test_passive_mode_interaction.py
```

测试将验证：
- 交互录制器功能
- 序列管理器的依赖分析
- 交互复现器的精确执行
- 验证机制的安全性检查

## 工作模式

### 执行模式

#### 被动模式（默认）
- **无感监控**: 在后台默默记录用户操作，不影响正常浏览
- **完整交互复现**: 能够记录并完整复现用户的操作序列（如登录、表单填写等）
- **智能依赖分析**: 自动识别操作间的依赖关系，确保正确的执行顺序
- **精确输入模拟**: 逐字符复现用户输入，完美处理需要前提条件的操作

#### 主动模式
- AI代理自主探索和测试
- 更深入的漏洞挖掘
- 适合授权渗透测试

### 浏览器池模式

#### 共享模式（推荐）
- 影子浏览器在主浏览器中创建新标签页
- 自动共享cookies、localStorage和session
- 支持测试需要登录的功能
- 资源消耗低

#### 独立模式
- 创建独立的headless浏览器实例
- 复制主浏览器的认证状态
- 更好的隔离性
- 适合敏感环境

## 安全注意事项

⚠️ **重要警告**：
- 只对您有权测试的网站进行扫描
- 必须配置白名单域名以避免意外扫描
- 不要在生产环境直接使用
- 注意扫描频率以避免对目标服务器造成压力

## 未来规划 (Roadmap)

Aegis 框架仍在快速演进中，以下是我们共同规划的、能带来质变的功能迭代方向：

### 🚀 架构演进与核心重构 (Architectural Evolution & Core Refactoring)

- [ ] **统一分析流程: 确立AI Agent的“总指挥”地位**
  - **目标**: 将`ScannerManager`改造为AI Agent可调用的工具，实现由AI根据上下文智能决策、触发特定扫描的统一分析流程。
  - **价值**: 消除当前分析路径的割裂，实现真正的“智能编排”，让AI成为驱动所有扫描行为的核心。

- [ ] **引入依赖注入 (DI) 与服务容器**
  - **目标**: 在`main.py`中创建全局“服务容器”，集中管理`LLMClient`, `BrowserPool`等核心服务，并以依赖注入方式传递给各工作模块。
  - **价值**: 大幅降低模块间耦合，提升代码的可测试性和可维护性。

- [ ] **分析逻辑服务化与代码整合**
  - **目标**: 将`AgentWorker`和`InteractionWorker`中重复的分析逻辑（如页面快照、调用扫描等）抽象成可复用的`AnalysisService`。
  - **价值**: 减少代码冗余，使核心工作模块的职责更单一、清晰。

### 🎯 功能增强与能力跃迁 (Feature Enhancement & Capability Leap)

- [ ] **DAST引擎的成熟化 (PoC驱动)**
  - **描述**: 将当前的DAST测试升级为一个可编排、支持复杂PoC的工作流引擎，使其接近Nuclei等专业工具的能力。
  - **已完成**:
    - [x] 将Payloads从硬编码重构为外部JSON/YAML文件。
    - [x] 实现了SSTI漏洞检测的原型。
    - [x] 实现了URL参数的增量分析原型。
  - **待办 (TODO)**:
    - [ ] **定义PoC格式**: 设计一套机器可读的YAML格式，用于描述多步请求、变量提取、复杂匹配器等。
    - [ ] **实现状态化引擎**: 支持在多步请求之间传递状态（如CSRF Token）。
    - [ ] **增强匹配器 (Matcher)**: 实现更强大的结果断言能力，支持基于状态码、响应头、正则表达式、DSL等多种条件的判断。
    - [ ] **支持带外检测 (OOB)**: 增加对SSRF等带外漏洞的检测支持。

- [ ] **核心引擎与AI能力**
  - **已完成**:
    - [x] **深化CDP与IAST集成**: 让AI能主动消费和理解来自`debug_events_q`的实时调试和IAST事件。
  - **待办 (TODO)**:
    - [ ] **实现“分析-验证”闭环**: 在高级DAST引擎的基础上，实现`情报收集 -> AI分析 -> AI生成PoC -> DAST执行 -> 验证结果`的完整闭环。
    - [ ] **实现AI工作记忆总结**: 在`AgentWorker`中增加“自我总结”步骤，解决长上下文限制。

### 🧩 易用性与流程优化 (Usability & Flow Optimization)
- [x] **优化导航与增量分析**: 引入"URL端点规范化"逻辑，避免对同一页面的重复性重量级分析。
- [x] **被动模式状态化重放**: 实现对用户连续操作链的记录与复现，确保对复杂交互的分析上下文绝对准确。
- [ ] **增强启动逻辑**: 优化启动行为，使其能自动发现并分析所有已打开的、在白名单内的标签页，并智能选择认证状态。