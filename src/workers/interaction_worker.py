import asyncio
import logging
import json
import os
import aiofiles
from typing import Dict, Any, Optional, List
from asyncio import Task
from openai import AsyncOpenAI
from playwright.async_api import Page, BrowserContext

from src.utils.browser_pool import BrowserPool
from src.tools import browser_tools, auth_tools
from src.tools.network_tools import NetworkSniffer
from src.sast_tools import secret_scanner, xss_scanner, crypto_detector
from src.prompts.prompt import get_interaction_analysis_prompt
from src.utils.ai_logger import log_ai_dialogue

class InteractionWorker:
    """
    无感被动交互分析器，只在用户进行页面交互操作时进行快照+分析。
    """

    def __init__(self, config: dict, browser_pool: BrowserPool, concurrency_semaphore: asyncio.Semaphore, input_q, output_q, debug_events_q=None):
        self.config = config
        self.browser_pool = browser_pool
        self.concurrency_semaphore = concurrency_semaphore
        self.input_q = input_q
        self.output_q = output_q
        self.debug_events_q = debug_events_q
        self.logger = logging.getLogger(self.__class__.__name__)
        self.js_hook_script = ""
        self.iast_findings: List[Dict[str, Any]] = []
        self._debug_listener_task: Optional[Task] = None
        
        passive_config = config.get('investigation_manager', {}).get('passive_mode', {})
        self.analysis_depth = passive_config.get('analysis_depth', 'deep')
        self.auto_security_testing = passive_config.get('auto_security_testing', True)
        self.interaction_types = passive_config.get('interaction_types', ['click', 'submit', 'input'])
        self.analysis_timeout = passive_config.get('analysis_timeout', 120)
        self.generate_interaction_reports = passive_config.get('generate_interaction_reports', True)
        self.enable_llm_analysis = config.get('interaction_analysis', {}).get('enable_llm', True)
        
        self.max_parallel_interactions = self.concurrency_semaphore._value
        self.interaction_history = []
        self.cumulative_findings = []
        self.last_report_time = 0
        self.report_interval = 60
        self.target_url = None
        
        llm_config = self.config.get('llm_service', {})
        if llm_config and llm_config.get('api_config'):
            self.llm_client = AsyncOpenAI(base_url=llm_config['api_config'].get('base_url'), api_key=llm_config['api_config'].get('api_key'))
        else:
            self.llm_client = None

    async def run(self):
        await self._load_js_hooks()
        self._debug_listener_task = asyncio.create_task(self._listen_for_debug_events())
        self.logger.info("InteractionWorker 开始运行，等待交互事件...")
        try:
            while True:
                interaction_event = await self.input_q.get()
                if interaction_event is None: break
                await self.handle_interaction_event(interaction_event)
                self.input_q.task_done()
        except asyncio.CancelledError:
            self.logger.info("InteractionWorker 任务被取消")
        finally:
            if self._debug_listener_task and not self._debug_listener_task.done():
                self._debug_listener_task.cancel()
            self.logger.info("InteractionWorker 已停止运行")

    async def _listen_for_debug_events(self):
        self.logger.info("IAST/CDP事件监听器已启动。" )
        try:
            while True:
                debug_event = await self.debug_events_q.get()
                self.logger.info(f"接收到IAST/CDP调试事件: {debug_event}")
                self.iast_findings.append(debug_event)
                self.debug_events_q.task_done()
        except asyncio.CancelledError:
            self.logger.info("IAST/CDP事件监听器已关闭。" )

    async def handle_interaction_event(self, event: Dict[str, Any]):
        if not self.auto_security_testing or event.get('interaction_type') not in self.interaction_types:
            return
        if not self.target_url:
            self.target_url = event.get('url')
        self.logger.info(f"接收到新的交互分析任务: {event.get('interaction_type')} on {event.get('url')}")
        asyncio.create_task(self._perform_analysis_workflow(event))

    async def _load_js_hooks(self):
        try:
            async with aiofiles.open('src/tools/js_hooks.js', mode='r', encoding='utf-8') as f:
                self.js_hook_script = await f.read()
                self.logger.info("IAST JS Hook脚本加载成功。" )
        except Exception as e:
            self.logger.error(f"加载IAST JS Hook脚本失败: {e}")

    async def _setup_page_for_analysis(self, page: Page):
        if self.js_hook_script:
            try:
                await page.expose_function("__aegis_iast_report__", lambda finding: self.debug_events_q.put_nowait(finding))
                await page.add_init_script(self.js_hook_script)
            except Exception as e:
                self.logger.error(f"为页面 {page.url} 注入IAST Hooks失败: {e}")

    async def _perform_analysis_workflow(self, event: Dict[str, Any]):
        context: Optional[BrowserContext] = None
        async with self.concurrency_semaphore:
            try:
                context = await self.browser_pool.acquire()
                page = await context.new_page()
                await self._setup_page_for_analysis(page)
                if event.get('auth_state'):
                    await auth_tools.inject_auth_state(page, event['auth_state'])
                await browser_tools.navigate(page, event['url'])
                
                snapshot = await self._create_interaction_snapshot(page, event)
                analysis_results = await self._run_full_analysis(page, snapshot, event)
                
                if self.generate_interaction_reports:
                    await self._accumulate_and_report(event, snapshot, analysis_results)
            except Exception as e:
                self.logger.error(f"交互分析工作流发生错误: {e}", exc_info=True)
            finally:
                if context:
                    await self.browser_pool.release(context)

    async def _run_full_analysis(self, page: Page, snapshot: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        try:
            return await asyncio.wait_for(
                self._perform_targeted_analysis(page, snapshot, event),
                timeout=self.analysis_timeout
            )
        except asyncio.TimeoutError:
            self.logger.warning(f"交互分析超时（{self.analysis_timeout}秒），返回基础SAST结果")
            return {'sast_findings': snapshot.get('sast_results', {}), 'llm_analysis': None}

    async def _accumulate_and_report(self, event, snapshot, analysis_results):
        new_findings = self._standardize_findings(event, snapshot, analysis_results)
        self.cumulative_findings.extend(new_findings)
        self.logger.info(f"累积了 {len(new_findings)} 个新发现，总计 {len(self.cumulative_findings)} 个发现")
        current_time = event.get('timestamp', 0)
        if current_time - self.last_report_time >= self.report_interval:
            await self._output_cumulative_report()
            self.last_report_time = current_time

    def _standardize_findings(self, event, snapshot, results) -> list:
        all_findings = []
        if results.get('llm_analysis'):
            llm_res = results['llm_analysis']
            finding = {
                'vulnerability': f"AI综合研判: {llm_res.get('risk_assessment')}",
                'severity': llm_res.get('risk_assessment', 'Informational'),
                'confidence': 'High',
                'description': llm_res.get('analysis_summary', 'N/A'),
                'recommendation': '\n'.join(llm_res.get('security_recommendations', [])),
                'attack_vectors': '\n'.join(llm_res.get('potential_attack_vectors', [])),
                'source': 'llm_analysis'
            }
            all_findings.append(finding)

        dast_results = results.get('shadow_browser_test_results', {})
        if dast_results.get('security_findings'):
            for finding in dast_results['security_findings']:
                std_finding = {
                    'vulnerability': finding.get('type', 'DAST Finding'),
                    'severity': finding.get('severity', 'Medium'),
                    'confidence': 'High',
                    'description': finding.get('description'),
                    'evidence': f"Payload: {finding.get('payload')}",
                    'source': 'dast_shadow_browser'
                }
                all_findings.append(std_finding)
        
        for finding in all_findings:
            finding.update({
                'url': event.get('url'),
                'interaction_type': event.get('interaction_type'),
                'element_selector': snapshot.get('target_element', {}).get('selector')
            })
        return all_findings

    async def _output_cumulative_report(self):
        if not self.cumulative_findings:
            self.logger.info("暂无发现，跳过报告输出")
            return
        report_data = {
            'worker': 'InteractionWorker-Cumulative',
            'source_context': {
                'initiator_url': self.target_url,
                'mode': 'passive',
                'total_interactions_analyzed': len(self.interaction_history)
            },
            'findings': self.cumulative_findings,
            'timestamp': asyncio.get_event_loop().time()
        }
        await self.output_q.put(report_data)
        self.logger.info(f"已输出包含 {len(self.cumulative_findings)} 个发现的累积报告。" )
        self.cumulative_findings = []

    async def _create_interaction_snapshot(self, page: Page, event: Dict[str, Any]) -> Dict[str, Any]:
        page_content = await browser_tools.get_web_content(page)
        sast_results = {
            'secrets': secret_scanner.find_secrets(page_content),
            'xss_sinks': xss_scanner.find_xss_sinks(page_content),
            'crypto': crypto_detector.detect_crypto_patterns(page_content)
        }
        return {
            "url": page.url,
            "title": await page.title(),
            "target_element": event.get('element_info', {}),
            "sast_results": sast_results,
            "interaction_type": event.get('interaction_type'),
            "timestamp": event.get('timestamp')
        }

    async def _perform_targeted_analysis(self, page: Page, snapshot: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        analysis_results = {'sast_findings': snapshot['sast_results']}
        if self.analysis_depth == 'deep':
            self.iast_findings.clear()
            await asyncio.sleep(0.5)

            results = await asyncio.gather(
                self._analyze_network_packets(page, snapshot, event),
                self._run_shadow_browser_test(page, snapshot, event),
                return_exceptions=True
            )
            analysis_results['network_packet_analysis'] = results[0] if not isinstance(results[0], Exception) else None
            analysis_results['shadow_browser_test_results'] = results[1] if not isinstance(results[1], Exception) else None
            
            analysis_results['iast_findings'] = self.iast_findings.copy()
            self.iast_findings.clear()

        if self.enable_llm_analysis:
            analysis_results['llm_analysis'] = await self._perform_llm_analysis(snapshot, event, analysis_results)
        return analysis_results

    async def _analyze_network_packets(self, page: Page, snapshot: Dict[str, Any], event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        sniffer = NetworkSniffer()
        try:
            await sniffer.start_capture(page)
            target_selector = snapshot.get('target_element', {}).get('selector')
            if target_selector:
                try:
                    interaction_type = event.get('interaction_type')
                    if interaction_type in ['click', 'submit']:
                        await page.click(target_selector, timeout=5000)
                    elif interaction_type == 'input':
                        await page.fill(target_selector, 'aegis_test_input', timeout=5000)
                        await page.press(target_selector, 'Enter')
                    await asyncio.sleep(2)
                except Exception as e:
                    self.logger.warning(f"模拟交互以捕获网络包失败: {e}")
            await sniffer.stop_capture(page)
            return sniffer.analyze_api_calls()
        except Exception as e:
            self.logger.error(f"网络数据包分析失败: {e}", exc_info=True)
            return None

    async def _run_shadow_browser_test(self, page: Page, snapshot: Dict[str, Any], event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return {'security_findings': []}

    async def _perform_llm_analysis(self, snapshot: Dict[str, Any], event: Dict[str, Any], results: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            level = self.config.get('llm_service', {}).get('reasoning_level', 'high')
            prompt = get_interaction_analysis_prompt(event.get('interaction_type'), snapshot, results, "分析用户交互点的安全风险，提供针对性的安全建议", level)
            llm_result = await self._call_llm(prompt)
            if 'error' in llm_result: return None
            return json.loads(llm_result['response'])
        except Exception as e:
            self.logger.error(f"LLM分析失败: {e}")
            return None

    async def _call_llm(self, prompt: str) -> Dict[str, Any]:
        if not self.llm_client: return {'error': 'LLM client not initialized'}
        try:
            cfg = self.config['llm_service']['api_config']
            messages = [{"role": "system", "content": "你是一位网络安全专家，擅长分析网页交互中的安全风险。"}, {"role": "user", "content": prompt}]
            response = await asyncio.wait_for(self.llm_client.chat.completions.create(model=cfg['model_name'], messages=messages, max_tokens=1500, temperature=0.5), timeout=cfg.get('timeout', 300))
            content = response.choices[0].message.content
            await log_ai_dialogue(prompt, content, self.config.get('logging', {}).get('ai_dialogues_file', './logs/ai_dialogues.jsonl'))
            return {'response': content}
        except Exception as e:
            self.logger.error(f"LLM调用失败: {e}")
            return {'error': str(e)}