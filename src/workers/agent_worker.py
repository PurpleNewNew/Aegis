import asyncio
import logging
import json
from openai import AsyncOpenAI
from playwright.async_api import BrowserContext, Page
from typing import List, Dict, Any, Callable
from asyncio import Queue, Semaphore

from src.prompts.prompt import get_agent_reasoning_prompt
from src.tools import browser_tools, network_tools, auth_tools, reporting_tools
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
        self.concurrency_semaphore = concurrency_semaphore # 接收统一的信号量
        self.output_q = output_q
        self.debug_events_q = debug_events_q
        self.on_complete = on_complete
        self.logger = logging.getLogger(f"Agent({start_url[:30]}...)")
        self.max_steps = 15
        self.final_findings: List[Dict[str, Any]] = []
        self.max_parallel_interactions = self.concurrency_semaphore._value # 获取最大并发数

        self.shared_state = shared_state if shared_state else SharedState()
        self.shared_state.current_url = start_url
        self.shared_state.goal = goal
        
        llm_config = self.config['llm_service']
        self.llm_client = AsyncOpenAI(base_url=llm_config['api_config']['base_url'], api_key=llm_config['api_config']['api_key'])

    async def _call_llm(self, prompt: str) -> Dict[str, Any]:
        """
        调用LLM进行决策，返回AI的思考和工具调用。
        """
        try:
            llm_config = self.config['llm_service']['api_config']
            model_name = llm_config['model_name']
            timeout = llm_config.get('timeout', 300)
            
            messages = [
                {
                    "role": "system",
                    "content": "你是一个专业的Web安全测试专家，擅长发现各种Web漏洞。请严格按照JSON格式返回决策。"
                },
                {
                    "role": "user",
                    "content": prompt
                }
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
                return {
                    "thought": "LLM响应解析失败，结束当前调查。",
                    "tool_call": {
                        "name": "finish_investigation",
                        "args": {"summary": "由于LLM响应解析错误，提前结束调查。"}
                    }
                }
                
        except asyncio.TimeoutError:
            self.logger.error("LLM调用超时")
            return {
                "thought": "LLM调用超时，结束当前调查。",
                "tool_call": {
                    "name": "finish_investigation",
                    "args": {"summary": "LLM调用超时，无法继续分析。"}
                }
            }
            
        except Exception as e:
            self.logger.error(f"LLM调用发生意外错误: {e}", exc_info=True)
            return {
                "thought": f"LLM调用失败: {str(e)}",
                "tool_call": {
                    "name": "finish_investigation",
                    "args": {"summary": f"LLM调用出现技术错误: {str(e)}"}
                }
            }
    
    async def _output_final_report(self):
        """
        生成最终报告并输出到队列。
        """
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
        # 使用统一的信号量来控制对浏览器池的访问
        async with self.concurrency_semaphore:
            self.logger.info(f"AgentWorker已获取信号量，开始执行任务。当前并发: {self.max_parallel_interactions - self.concurrency_semaphore._value}/{self.max_parallel_interactions}")
            execution_mode = self.config.get('investigation_manager', {}).get('execution_mode', 'autonomous')
            
            if execution_mode == 'passive':
                await self._run_passive_mode()
            else:
                await self._run_autonomous_mode()
    
    async def _run_passive_mode(self):
        self.logger.info(f"被动模式：为目标 '{self.goal}' 准备基础环境。")
        context: BrowserContext | None = None
        try:
            context = await self.browser_pool.acquire()
            page = await context.new_page()

            if self.auth_state:
                await auth_tools.inject_auth_state(page, self.auth_state)
            
            await browser_tools.navigate(page, self.start_url)
            self.logger.info("被动模式：基础环境准备完成，等待用户交互事件...")
            
            # 在被动模式下，保持页面活跃，不退出循环，直到任务被取消
            await asyncio.Event().wait()
            
        except asyncio.CancelledError:
            self.logger.info("被动模式任务被取消，正在关闭...")
        except Exception as e:
            self.logger.error(f"被动模式初始化时发生错误: {e}", exc_info=True)
        finally:
            if context:
                await self.browser_pool.release(context)
            self.logger.info(f"被动模式：对 '{self.start_url}' 的监控已停止。")
    
    async def _run_autonomous_mode(self):
        self.logger.info(f"自主模式：开始对目标 '{self.goal}' 进行调查。")
        contexts = []
        try:
            max_parallel = min(3, self.browser_pool.pool_size)
            self.logger.info(f"启动并行测试模式，使用 {max_parallel} 个浏览器实例")
            
            pages = [] # 修正：初始化pages列表
            for i in range(max_parallel):
                context = await self.browser_pool.acquire()
                pages.append(await context.new_page())
                contexts.append(context)
                
                if self.auth_state:
                    await auth_tools.inject_auth_state(pages[i], self.auth_state)
                
                await browser_tools.navigate(pages[i], self.start_url)
                self.logger.info(f"浏览器实例 {i+1} 初始侦察阶段开始...")
            
            main_page = pages[0]
            page_content = await browser_tools.get_web_content(main_page)
            interactive_elements = await browser_tools.get_interactive_elements(main_page)
            sast_results = {
                'secrets': secret_scanner.find_secrets(page_content),
                'xss_sinks': xss_scanner.find_xss_sinks(page_content),
                'crypto': crypto_detector.detect_crypto_patterns(page_content)
            }
            recon_snapshot = {
                "page_content_summary": page_content[:1000] + "...",
                "interactive_elements": interactive_elements,
                "sast_results": sast_results
            }
            self.logger.info("初始侦察完成。进入行动循环。")

            history = []
            step = 0
            
            while step < self.max_steps:
                self.logger.info(f"--- [行动步骤 {step+1}/{self.max_steps}] ---")
                step += 1

                current_observation = f"当前页面状态:\n- URL: {main_page.url}\n- 标题: {await main_page.title()}\n"
                current_observation += f"侦察快照:\n{json.dumps(recon_snapshot, ensure_ascii=False, indent=2)}"
                
                prompt = get_agent_reasoning_prompt(
                    goal=self.goal, 
                    history=history, 
                    observation=current_observation,
                    sast_results=recon_snapshot.get('sast_results', {}),
                    iast_findings=[],
                    long_term_memories=[]
                )
                ai_decision = await self._call_llm(prompt)
                thought = ai_decision.get('thought', '')
                tool_call = ai_decision.get('tool_call')
                self.logger.info(f"AI决策: {thought}")

                if not tool_call or not (tool_name := tool_call.get('name')):
                    self.logger.warning("AI未能做出有效决策，终止。")
                    break

                tool_args = tool_call.get('args', {})
                self.logger.info(f"执行工具: `{tool_name}`，参数: `{tool_args}`")

                if tool_name == 'finish_investigation':
                    break
                elif tool_name == 'report_finding':
                    self.final_findings.append(tool_args)
                    observation = f"发现已记录: {tool_args.get('vulnerability')}"
                else:
                    tool_function = getattr(browser_tools, tool_name, None) or getattr(network_tools, tool_name, None)
                    if tool_function:
                        try:
                            observation = await tool_function(main_page, **tool_args)
                        except TypeError as e:
                            observation = f"工具调用错误: {str(e)}"
                    else:
                        observation = f"错误：不存在名为 '{tool_name}' 的工具。"
                
                history.append({"thought": thought, "tool_call": tool_call, "observation": observation})

            self.logger.info("调查循环结束。")
            await self._output_final_report()
            
        except Exception as e:
            self.logger.error(f"自主模式运行中发生严重错误: {e}", exc_info=True)
        finally:
            for context in contexts:
                await self.browser_pool.release(context)
            self.on_complete(self.start_url)
            self.logger.info(f"自主模式：对 '{self.start_url}' 的调查任务已彻底结束。")
