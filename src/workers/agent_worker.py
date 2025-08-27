import asyncio
import logging
import json
import aiofiles
from openai import AsyncOpenAI
from playwright.async_api import BrowserContext, Page
from typing import List, Dict, Any, Callable, Optional
from asyncio import Queue, Semaphore, Task

from src.prompts.prompt import get_agent_reasoning_prompt
from src.tools import browser_tools, auth_tools
from src.tools.network_tools import NetworkSniffer
from src.scanners import XSSStaticScanner, JSReverseScanner, ScannerManager
from src.utils.unified_crypto_analyzer import UnifiedCryptoAnalyzer
from src.utils.browser_pool import BrowserPool
from src.utils.ai_logger import log_ai_dialogue
from src.utils.fingerprinter import get_preliminary_fingerprint
from src.utils.parallel_executor import ParallelTaskExecutor, SmartParallelOrchestrator
from src.models.shared_state import SharedState

class AgentWorker:
    """
    Aegis的最终版“AI指挥官”代理，实现了“真登录”和“高效侦察”逻辑。
    """

    def __init__(self, goal: str, start_url: str, auth_state: Dict, config: dict, browser_pool: BrowserPool, concurrency_semaphore: Semaphore, output_q: Queue, debug_events_q: Queue, on_complete: Callable[[str], None], shared_state: SharedState = None):
        self.goal = goal
        self.start_url = start_url
        self.auth_state = auth_state
        self.config = config
        self.browser_pool = browser_pool
        self.concurrency_semaphore = concurrency_semaphore
        self.output_q = output_q
        self.debug_events_q = debug_events_q
        self.on_complete = on_complete
        self.logger = logging.getLogger(f"Agent({start_url[:30]}...)")
        self.max_steps = 15
        self.final_findings: List[Dict[str, Any]] = []
        self.iast_findings: List[Dict[str, Any]] = []
        self.max_parallel_interactions = self.concurrency_semaphore._value
        self._debug_listener_task: Optional[Task] = None
        self.js_hook_script = ""
        self.network_sniffer = NetworkSniffer()

        self.shared_state = shared_state if shared_state else SharedState()
        self.shared_state.current_url = start_url
        self.shared_state.goal = goal
        
        llm_config = self.config['llm_service']
        self.llm_client = AsyncOpenAI(base_url=llm_config['api_config']['base_url'], api_key=llm_config['api_config']['api_key'])
        
        # 初始化统一的加密分析器
        self.crypto_analyzer = UnifiedCryptoAnalyzer(self.config)
        
        # 初始化扫描器
        self.xss_scanner = XSSStaticScanner(self.config)
        self.js_scanner = JSReverseScanner(self.config)
        
        # 并行测试相关
        self.parallel_pages = []
        self.parallel_executor = None
        self.orchestrator = SmartParallelOrchestrator(self)

    async def _load_js_hooks(self):
        try:
            async with aiofiles.open('src/tools/js_hooks.js', mode='r', encoding='utf-8') as f:
                self.js_hook_script = await f.read()
                self.logger.info("IAST JS Hook脚本加载成功。")
        except Exception as e:
            self.logger.error(f"加载IAST JS Hook脚本失败: {e}")

    async def _listen_for_debug_events(self):
        self.logger.info("IAST/CDP事件监听器已启动。")
        try:
            while True:
                debug_event = await self.debug_events_q.get()
                self.logger.info(f"接收到IAST/CDP调试事件: {debug_event}")
                self.iast_findings.append(debug_event)
                self.debug_events_q.task_done()
        except asyncio.CancelledError:
            self.logger.info("IAST/CDP事件监听器已关闭。")

    async def _call_llm(self, prompt: str) -> Dict[str, Any]:
        try:
            llm_config = self.config['llm_service']['api_config']
            model_name = llm_config['model_name']
            timeout = llm_config.get('timeout', 300)
            messages = [
                {"role": "system", "content": "你是一个专业的Web安全测试专家，擅长发现各种Web漏洞。请严格按照JSON格式返回决策。"},
                {"role": "user", "content": prompt}
            ]
            self.logger.info("正在调用LLM进行决策...")
            response = await asyncio.wait_for(
                self.llm_client.chat.completions.create(
                    model=model_name,
                    messages=messages,
                    temperature=0.7,
                    max_tokens=2000
                ),
                timeout=timeout
            )
            content = response.choices[0].message.content.strip()
            self.logger.info(f"LLM响应长度: {len(content)} 字符")
            ai_log_file = self.config.get('logging', {}).get('ai_dialogues_file', './logs/ai_dialogues.jsonl')
            await log_ai_dialogue(prompt, content, ai_log_file)
            try:
                json_content = content
                if '```json' in content:
                    json_content = content.split('```json')[1].split('```')[0].strip()
                if '{' in json_content:
                    start = json_content.find('{')
                    end = json_content.rfind('}') + 1
                    if start >= 0 and end > start:
                        json_content = json_content[start:end]
                ai_decision = json.loads(json_content)
                return ai_decision
            except (json.JSONDecodeError, ValueError) as e:
                self.logger.error(f"LLM响应JSON解析失败: {e}")
                return {"thought": "LLM响应解析失败，结束当前调查。", "tool_call": {"name": "finish_investigation", "args": {"summary": "由于LLM响应解析错误，提前结束调查。"}}}
        except asyncio.TimeoutError:
            self.logger.error("LLM调用超时")
            return {"thought": "LLM调用超时，结束当前调查。", "tool_call": {"name": "finish_investigation", "args": {"summary": "LLM调用超时，无法继续分析。"}}}
        except Exception as e:
            self.logger.error(f"LLM调用发生意外错误: {e}", exc_info=True)
            return {"thought": f"LLM调用失败: {str(e)}", "tool_call": {"name": "finish_investigation", "args": {"summary": f"LLM调用出现技术错误: {str(e)}"}}}
    
    async def _output_final_report(self):
        try:
            architecture_fingerprint = get_preliminary_fingerprint(self.start_url)
            architecture_summary = ', '.join(architecture_fingerprint) if architecture_fingerprint else '未知架构'
            report_data = {
                'worker': f'AgentWorker({self.start_url[:30]}...)',
                'source_context': {
                    'initiator_url': self.start_url,
                    'goal': self.goal,
                    'investigation_completed': True,
                    'steps_taken': min(len(getattr(self, 'history', [])), self.max_steps)
                },
                'architecture': architecture_summary,
                'findings': self.final_findings,
                'timestamp': asyncio.get_event_loop().time(),
                'summary': {
                    'total_findings': len(self.final_findings),
                    'critical_findings': len([f for f in self.final_findings if f.get('severity') == 'Critical']),
                    'high_findings': len([f for f in self.final_findings if f.get('severity') == 'High']),
                    'medium_findings': len([f for f in self.final_findings if f.get('severity') == 'Medium']),
                    'low_findings': len([f for f in self.final_findings if f.get('severity') == 'Low']),
                    'info_findings': len([f for f in self.final_findings if f.get('severity') == 'Informational'])
                }
            }
            await self.output_q.put(report_data)
            self.logger.info(f"成功输出最终报告：{len(self.final_findings)} 个发现")
        except Exception as e:
            self.logger.error(f"输出最终报告时发生错误: {e}", exc_info=True)

    async def run(self):
        await self._load_js_hooks()
        self._debug_listener_task = asyncio.create_task(self._listen_for_debug_events())
        try:
            async with self.concurrency_semaphore:
                self.logger.info(f"AgentWorker已获取信号量，开始执行任务。")
                execution_mode = self.config.get('investigation_manager', {}).get('execution_mode', 'autonomous')
                if execution_mode == 'passive':
                    await self._run_passive_mode()
                else:
                    await self._run_autonomous_mode()
        finally:
            if self._debug_listener_task and not self._debug_listener_task.done():
                self._debug_listener_task.cancel()
    
    async def _setup_page_for_analysis(self, page: Page):
        if self.js_hook_script:
            try:
                await page.expose_function("__aegis_iast_report__", lambda finding: self.debug_events_q.put_nowait(finding))
                await page.add_init_script(self.js_hook_script)
            except Exception as e:
                self.logger.error(f"为页面 {page.url} 注入IAST Hooks失败: {e}")

    async def _run_passive_mode(self):
        self.logger.info(f"被动模式：为目标 '{self.goal}' 准备基础环境。")
        context: Optional[BrowserContext] = None
        try:
            context = await self.browser_pool.acquire()
            page = await context.new_page()
            await self._setup_page_for_analysis(page)
            if self.auth_state:
                await auth_tools.inject_auth_state(page, self.auth_state)
            await browser_tools.navigate(page, self.start_url)
            self.logger.info("被动模式：基础环境准备完成，等待用户交互事件...")
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.logger.info("被动模式任务被取消。")
        finally:
            if context:
                await self.browser_pool.release(context)
    
    async def _run_autonomous_mode(self):
        self.logger.info(f"自主模式：开始对目标 '{self.goal}' 进行调查。")
        contexts = []
        try:
            main_page = await self._setup_autonomous_pages(contexts)
            
            # 初始化并行执行器
            if len(self.parallel_pages) > 1:
                self.parallel_executor = ParallelTaskExecutor(self.parallel_pages, self.config)
                self.logger.info(f"已初始化并行执行器，可使用 {len(self.parallel_pages)} 个影子浏览器")
            
            recon_snapshot = await self._initial_reconnaissance(main_page)
            self.logger.info("初始侦察完成。进入行动循环。" )

            history = []
            network_analysis_history = []
            for step in range(self.max_steps):
                self.logger.info(f"--- [行动步骤 {step+1}/{self.max_steps}] ---")
                
                # 如果有多个浏览器，考虑并行任务
                if self.parallel_executor and len(self.parallel_pages) > 1:
                    # 检查是否需要执行并行任务
                    parallel_decision = await self._check_parallel_opportunity(recon_snapshot)
                    if parallel_decision.get('execute_parallel', False):
                        self.logger.info("执行并行测试任务...")
                        parallel_results = await self._execute_parallel_tasks(parallel_decision)
                        # 将并行结果加入历史
                        history.append({
                            'type': 'parallel_execution',
                            'results': parallel_results,
                            'timestamp': asyncio.get_event_loop().time()
                        })
                        continue
                
                # 单步推理和执行
                parallel_mode = len(self.parallel_pages) > 1
                prompt = self._build_reasoning_prompt(history, recon_snapshot, network_analysis_history, parallel_mode=parallel_mode)
                ai_decision = await self._call_llm(prompt)
                thought = ai_decision.get('thought', '')
                tool_call = ai_decision.get('tool_call')
                self.logger.info(f"AI决策: {thought}")

                if not tool_call or not (tool_name := tool_call.get('name')):
                    self.logger.warning("AI未能做出有效决策，终止。" )
                    break
                
                await self.network_sniffer.start_capture(main_page)
                observation = await self._execute_tool(main_page, tool_call)
                await asyncio.sleep(1)
                await self.network_sniffer.stop_capture(main_page)
                
                network_analysis = self.network_sniffer.analyze_api_calls()
                network_analysis_history.append(network_analysis)
                self.logger.info(f"网络分析完成: 捕获 {network_analysis['summary']['total_requests']} 个请求。" )

                history.append({"thought": thought, "tool_call": tool_call, "observation": observation})
                if tool_name == 'finish_investigation': break

            await self._output_final_report()
        except Exception as e:
            self.logger.error(f"自主模式运行中发生严重错误: {e}", exc_info=True)
        finally:
            for context in contexts:
                await self.browser_pool.release(context)
            self.on_complete(self.start_url)

    async def _setup_autonomous_pages(self, contexts: list) -> Page:
        # 动态确定并行浏览器数量
        execution_mode = self.config.get('investigation_manager', {}).get('execution_mode', 'autonomous')
        
        if execution_mode == 'autonomous':
            # 在自主模式下，让AI决定需要多少个并行浏览器
            # 默认使用最小值：2个，但不超过池大小
            max_parallel = min(2, self.browser_pool.pool_size)
        else:
            # 其他模式使用固定数量
            max_parallel = min(3, self.browser_pool.pool_size)
        
        self.logger.info(f"设置 {max_parallel} 个并行浏览器进行测试")
        
        pages = []
        for i in range(max_parallel):
            context = await self.browser_pool.acquire()
            page = await context.new_page()
            contexts.append(context)
            pages.append(page)
            await self._setup_page_for_analysis(page)
            if self.auth_state:
                await auth_tools.inject_auth_state(page, self.auth_state)
            await browser_tools.navigate(page, self.start_url)
            
            # 为每个页面设置唯一标识
            await page.evaluate(f"""() => {{
                window.shadowBrowserId = {i+1};
                console.log('Shadow Browser {i+1} initialized');
            }}""")
        
        self.parallel_pages = pages  # 保存引用供后续使用
        return pages[0]

    async def _initial_reconnaissance(self, page: Page) -> dict:
        page_content = await browser_tools.get_web_content(page)
        
        # 使用统一的加密分析器
        crypto_findings = await self.crypto_analyzer.analyze_crypto(
            code=page_content,
            context={'url': page.url},
            analysis_modes=['static']
        )
        
        # 使用新的扫描器架构
        xss_result = await self.xss_scanner.scan(page_content, context={'url': page.url})
        js_result = await self.js_scanner.scan(page_content, context={'url': page.url})
        
        sast_results = {
            'secrets': [vuln.to_dict() for vuln in js_result.vulnerabilities if vuln.type.value == 'secret_exposure'],
            'xss_sinks': [vuln.to_dict() for vuln in xss_result.vulnerabilities],
            'crypto': [f.__dict__ for f in crypto_findings]  # 转换为字典格式
        }
        return {
            "url": page.url,
            "title": await page.title(),
            "page_content_summary": page_content[:1000] + "...",
            "interactive_elements": await browser_tools.get_interactive_elements(page),
            "sast_results": sast_results
        }

    def _build_reasoning_prompt(self, history, recon, net_history, parallel_mode=False) -> str:
        current_observation = f"当前页面状态:\n- URL: {recon.get('url', self.start_url)}\n- 标题: {recon.get('title', 'N/A')}\n"
        current_observation += f"侦察快照:\n{json.dumps(recon.get('interactive_elements'), ensure_ascii=False, indent=2)}"
        
        reasoning_level = self.config.get('llm_service', {}).get('reasoning_level', 'high')
        
        prompt = get_agent_reasoning_prompt(
            goal=self.goal,
            history=history,
            observation=current_observation,
            sast_results=recon.get('sast_results', {}),
            iast_findings=self.iast_findings,
            network_analysis=net_history[-1] if net_history else None,
            long_term_memories=[],
            reasoning_level=reasoning_level,
            parallel_mode=parallel_mode,
            available_browsers=len(self.parallel_pages) if parallel_mode else 1
        )
        self.iast_findings.clear()
        return prompt

    async def _execute_tool(self, page: Page, tool_call: dict) -> str:
        tool_name = tool_call.get('name')
        tool_args = tool_call.get('args', {})
        self.logger.info(f"执行工具: `{tool_name}`, 参数: `{tool_args}`")

        if tool_name == 'report_finding':
            self.final_findings.append(tool_args)
            return f"发现已记录: {tool_args.get('vulnerability')}"
        
        # JS逆向工具
        elif tool_name in ['analyze_js_crypto', 'detect_crypto_functions', 'analyze_network_crypto']:
            return await self._execute_js_reverse_tool(page, tool_name, tool_args)
        
        tool_function = getattr(browser_tools, tool_name, None)
        if tool_function:
            try:
                return await tool_function(page, **tool_args)
            except TypeError as e:
                return f"工具调用错误: {str(e)}"
        return f"错误：不存在名为 '{tool_name}' 的工具。"

    async def _execute_js_reverse_tool(self, page: Page, tool_name: str, tool_args: dict) -> str:
        """执行JS逆向相关工具"""
        from src.prompts.js_analysis_prompts import get_js_analysis_prompt, get_js_crypto_detection_prompt, get_network_crypto_analysis_prompt
        
        try:
            if tool_name == 'analyze_js_crypto':
                # 获取当前页面的JS上下文
                js_context = await page.evaluate("""
                    () => {
                        // 获取当前函数的上下文
                        const error = new Error();
                        const stack = error.stack || '';
                        const lines = stack.split('\\n');
                        const functionCalls = [];
                        
                        for (let i = 3; i < Math.min(lines.length, 8); i++) {
                            const match = lines[i].match(/at\\s+(.+?)\\s+\\((.+?):(\\d+):(\\d+)\\)/);
                            if (match) {
                                functionCalls.push(match[1]);
                            }
                        }
                        
                        return {
                            url: window.location.href,
                            functionCalls: functionCalls,
                            source: document.documentElement.outerHTML
                        };
                    }
                """)
                
                # 构建分析提示词
                prompt = get_js_analysis_prompt(
                    code_context=js_context.get('source', ''),
                    variables={},
                    url=js_context.get('url', page.url),
                    function_name=tool_args.get('function_name', ''),
                    call_stack=js_context.get('functionCalls', []),
                    reasoning_level=self.config.get('llm_service', {}).get('reasoning_level', 'medium')
                )
                
                # 发送给LLM分析
                response = await self.llm_client.send_message(prompt)
                
                # 尝试解析JSON响应
                try:
                    import json
                    result = json.loads(response)
                    if result.get('analysis') == '无关':
                        return "未发现相关的加密或安全机制"
                    
                    # 格式化分析结果
                    findings = result.get('findings', [])
                    summary = f"JS逆向分析完成。发现 {len(findings)} 个相关点：\n"
                    for finding in findings[:3]:  # 限制显示数量
                        summary += f"- {finding.get('type', '未知')}: {finding.get('description', '')[:100]}...\n"
                    
                    return summary
                except:
                    return f"JS逆向分析结果：{response[:500]}..."
                    
            elif tool_name == 'detect_crypto_functions':
                # 获取页面源码
                page_source = await page.content()
                
                prompt = get_js_crypto_detection_prompt(
                    page_source=page_source,
                    url=page.url,
                    reasoning_level=self.config.get('llm_service', {}).get('reasoning_level', 'medium')
                )
                
                response = await self.llm_client.send_message(prompt)
                
                try:
                    import json
                    result = json.loads(response)
                    functions = result.get('crypto_functions', [])
                    if functions:
                        summary = f"检测到 {len(functions)} 个加密相关函数：\n"
                        for func in functions[:5]:  # 限制显示数量
                            summary += f"- {func.get('name')} ({func.get('type')}) - {func.get('confidence')} 置信度\n"
                        return summary
                    else:
                        return "未检测到加密相关函数"
                except:
                    return f"加密函数检测结果：{response[:300]}..."
                    
            elif tool_name == 'analyze_network_crypto':
                # 获取网络请求数据
                # 这里需要从网络数据队列中获取相关信息
                network_data = []
                
                prompt = get_network_crypto_analysis_prompt(
                    requests=network_data,
                    url=page.url
                )
                
                response = await self.llm_client.send_message(prompt)
                
                try:
                    import json
                    result = json.loads(response)
                    issues = result.get('security_issues', [])
                    if issues:
                        summary = f"网络加密分析发现 {len(issues)} 个安全问题：\n"
                        for issue in issues:
                            summary += f"- [{issue.get('severity')}] {issue.get('description')}\n"
                        return summary
                    else:
                        return "网络加密分析未发现明显安全问题"
                except:
                    return f"网络加密分析结果：{response[:300]}..."
                    
        except Exception as e:
            self.logger.error(f"JS逆向工具执行失败: {e}")
            return f"JS逆向分析失败: {str(e)}"

    async def _check_parallel_opportunity(self, recon_snapshot: Dict) -> Dict[str, Any]:
        """检查是否存在并行测试机会"""
        if not self.orchestrator or len(self.parallel_pages) <= 1:
            return {'execute_parallel': False}
        
        # 分析页面内容，寻找并行测试机会
        page_analysis = {
            'url': self.start_url,
            'title': recon_snapshot.get('title', ''),
            'content_preview': recon_snapshot.get('content', '')[:1000],
            'forms': recon_snapshot.get('forms', []),
            'links': recon_snapshot.get('links', []),
            'buttons': recon_snapshot.get('interactive_elements', [])
        }
        
        # 让AI决定是否需要并行测试
        strategy = await self.orchestrator.create_parallel_strategy(
            page_analysis, 
            len(self.parallel_pages)
        )
        
        # 如果有并行任务，返回执行决策
        if strategy.get('parallel_tasks'):
            return {
                'execute_parallel': True,
                'strategy': strategy,
                'available_browsers': len(self.parallel_pages)
            }
        
        return {'execute_parallel': False}

    async def _execute_parallel_tasks(self, decision: Dict[str, Any]) -> List[Dict[str, Any]]:
        """执行并行任务"""
        if not self.parallel_executor:
            return []
        
        strategy = decision.get('strategy', {})
        parallel_tasks = strategy.get('parallel_tasks', [])
        
        if not parallel_tasks:
            return []
        
        # 执行并行任务
        results = await self.parallel_executor.execute_parallel_tasks(parallel_tasks)
        
        self.logger.info(f"并行执行完成，共 {len(results)} 个结果")
        
        # 分析结果，寻找安全漏洞
        for result in results:
            if result.get('success'):
                # 这里可以添加特定的安全检查逻辑
                pass
        
        return results
