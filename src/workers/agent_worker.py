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
from src.sast_tools import secret_scanner, xss_scanner, crypto_detector
from src.utils.browser_pool import BrowserPool
from src.utils.ai_logger import log_ai_dialogue
from src.utils.fingerprinter import get_preliminary_fingerprint
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
            recon_snapshot = await self._initial_reconnaissance(main_page)
            self.logger.info("初始侦察完成。进入行动循环。" )

            history = []
            network_analysis_history = []
            for step in range(self.max_steps):
                self.logger.info(f"--- [行动步骤 {step+1}/{self.max_steps}] ---")
                prompt = self._build_reasoning_prompt(history, recon_snapshot, network_analysis_history)
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
        max_parallel = min(3, self.browser_pool.pool_size)
        pages = []
        for _ in range(max_parallel):
            context = await self.browser_pool.acquire()
            page = await context.new_page()
            contexts.append(context)
            pages.append(page)
            await self._setup_page_for_analysis(page)
            if self.auth_state:
                await auth_tools.inject_auth_state(page, self.auth_state)
            await browser_tools.navigate(page, self.start_url)
        return pages[0]

    async def _initial_reconnaissance(self, page: Page) -> dict:
        page_content = await browser_tools.get_web_content(page)
        sast_results = {
            'secrets': secret_scanner.find_secrets(page_content),
            'xss_sinks': xss_scanner.find_xss_sinks(page_content),
            'crypto': crypto_detector.detect_crypto_patterns(page_content)
        }
        return {
            "url": page.url,
            "title": await page.title(),
            "page_content_summary": page_content[:1000] + "...",
            "interactive_elements": await browser_tools.get_interactive_elements(page),
            "sast_results": sast_results
        }

    def _build_reasoning_prompt(self, history, recon, net_history) -> str:
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
            reasoning_level=reasoning_level
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
        
        tool_function = getattr(browser_tools, tool_name, None)
        if tool_function:
            try:
                return await tool_function(page, **tool_args)
            except TypeError as e:
                return f"工具调用错误: {str(e)}"
        return f"错误：不存在名为 '{tool_name}' 的工具。"
