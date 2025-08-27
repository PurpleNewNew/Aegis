import asyncio
import logging
import json
import os
import aiofiles
import yaml
from typing import Dict, Any, Optional, List
from asyncio import Task
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from openai import AsyncOpenAI
from playwright.async_api import Page, BrowserContext, Error as PlaywrightError

from src.utils.browser_pool import BrowserPool
from src.tools import browser_tools, auth_tools
from src.tools.network_tools import NetworkSniffer
from src.scanners import XSSStaticScanner, JSReverseScanner, ScannerManager
from src.utils.unified_crypto_analyzer import UnifiedCryptoAnalyzer
from src.prompts.interaction_prompts import get_interaction_analysis_prompt
from src.utils.ai_logger import log_ai_dialogue
from src.utils.interaction_replayer import InteractionReplayer
from src.utils.interaction_sequence_manager import InteractionValidator
from src.utils.retry_utils import retry_async, RetryManager

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
        
        # 线程安全锁
        self.iast_findings_lock = asyncio.Lock()
        self.findings_lock = asyncio.Lock()
        self.history_lock = asyncio.Lock()
        
        # 重试管理器
        self.retry_manager = RetryManager(
            max_attempts=3,
            base_delay=1.0,
            max_delay=30.0,
            backoff_factor=2.0
        )
        
        llm_config = self.config.get('llm_service', {})
        if llm_config and llm_config.get('api_config'):
            self.llm_client = AsyncOpenAI(base_url=llm_config['api_config'].get('base_url'), api_key=llm_config['api_config'].get('api_key'))
        else:
            self.llm_client = None
        
        # 初始化统一的加密分析器
        self.crypto_analyzer = UnifiedCryptoAnalyzer(self.config)
        
        # 初始化扫描器管理器
        self.scanner_manager = ScannerManager(self.config)
        self.xss_scanner = XSSStaticScanner(self.config)
        self.js_scanner = JSReverseScanner(self.config)

    async def run(self):
        await self._load_js_hooks()
        self._debug_listener_task = asyncio.create_task(self._listen_for_debug_events())
        self.logger.info("InteractionWorker 开始运行，等待事件...")

    async def _listen_for_debug_events(self):
        self.logger.info("IAST/CDP事件监听器已启动。")
        try:
            while True:
                debug_event = await self.debug_events_q.get()
                self.logger.info(f"接收到IAST/CDP调试事件: {debug_event}")
                async with self.iast_findings_lock:
                    self.iast_findings.append(debug_event)
                self.debug_events_q.task_done()
        except asyncio.CancelledError:
            self.logger.info("IAST/CDP事件监听器已关闭。")

    async def analyze_interaction_chain(self, event_chain: List[Dict[str, Any]]):
        if not self.auto_security_testing or not event_chain:
            return
        
        last_event = event_chain[-1]
        if not self.target_url:
            self.target_url = last_event.get('url')
        
        self.logger.info(f"接收到包含 {len(event_chain)} 个事件的[交互链]分析任务，最终动作为: {last_event.get('interaction_type')} on {last_event.get('url')}")
        asyncio.create_task(self._perform_analysis_workflow(event_chain))

    async def analyze_interaction_sequence(self, sequence_data: Dict[str, Any]):
        """分析完整的交互序列"""
        if not self.auto_security_testing:
            return
        
        url = sequence_data.get('url')
        sequence = sequence_data.get('sequence', [])
        auth_state = sequence_data.get('auth_state')
        
        if not url or not sequence:
            return
        
        if not self.target_url:
            self.target_url = url
        
        self.logger.info(f"接收到包含 {len(sequence)} 个操作的[交互序列]分析任务 on {url}")
        asyncio.create_task(self._perform_sequence_analysis_workflow(url, sequence, auth_state))

    async def analyze_url(self, nav_info: Dict[str, Any]):
        if not self.auto_security_testing:
            return
        
        url = nav_info.get('url')
        self.logger.info(f"接收到新的[URL]分析任务: {url}")
        asyncio.create_task(self._test_url_params(url, nav_info.get('auth_state')))

    async def _load_js_hooks(self):
        try:
            async with aiofiles.open('src/tools/unified_hooks.js', mode='r', encoding='utf-8') as f:
                self.js_hook_script = await f.read()
                self.logger.info("IAST JS Hook脚本加载成功。")
        except Exception as e:
            self.logger.error(f"加载IAST JS Hook脚本失败: {e}")

    async def _setup_page_for_analysis(self, page: Page):
        if self.js_hook_script:
            try:
                await page.expose_function("__aegis_iast_report__", lambda finding: self.debug_events_q.put_nowait(finding))
                await page.add_init_script(self.js_hook_script)
            except Exception as e:
                self.logger.error(f"为页面 {page.url} 注入IAST Hooks失败: {e}")

    @retry_async(max_attempts=3, delay=2.0, exceptions=(Exception,))
    async def _perform_analysis_workflow(self, event_chain: List[Dict[str, Any]]):
        context: Optional[BrowserContext] = None
        url = None
        from_pool = False
        
        async with self.concurrency_semaphore:
            try:
                # Try to get domain-specific context if available
                url = event_chain[0].get('url', '')
                if hasattr(self.browser_pool, 'create_context_for_domain'):
                    context = await self.retry_manager.execute(
                        self.browser_pool.create_context_for_domain,
                        url,
                        exceptions=(ConnectionError, TimeoutError, Exception)
                    )
                else:
                    context = await self.retry_manager.execute(
                        self.browser_pool.acquire,
                        exceptions=(ConnectionError, TimeoutError, Exception)
                    )
                    from_pool = True
                    
                page = await context.new_page()
                await self._setup_page_for_analysis(page)

                initial_event = event_chain[0]
                if initial_event.get('auth_state'):
                    # Use enhanced auth injection with retry logic
                    await auth_tools.inject_auth_state(page, initial_event['auth_state'])
                    # Also set up retry on navigation
                    await auth_tools.inject_with_retry_on_navigation(page, initial_event['auth_state'])
                
                await browser_tools.navigate(page, initial_event['url'])

                sniffer = NetworkSniffer()
                await sniffer.start_capture(page)

                for event in event_chain:
                    self.logger.info(f"重放操作: {event.get('interaction_type')} on {event.get('element_info', {}).get('selector')}")
                    try:
                        await self._replay_single_interaction(page, event)
                    except Exception as e:
                        self.logger.warning(f"重放操作失败: {e}")
                
                await sniffer.stop_capture(page)
                network_analysis = sniffer.analyze_api_calls()

                final_event = event_chain[-1]
                snapshot = await self._create_interaction_snapshot(page, final_event)
                
                analysis_results = await self._run_full_analysis(page, snapshot, final_event)
                analysis_results['network_packet_analysis'] = network_analysis

                if self.enable_llm_analysis:
                    analysis_results['llm_analysis'] = await self._perform_llm_analysis(snapshot, final_event, analysis_results)

                if self.generate_interaction_reports:
                    await self._accumulate_and_report(final_event, snapshot, analysis_results)

            except Exception as e:
                self.logger.error(f"状态化重放分析工作流发生错误: {e}", exc_info=True)
            finally:
                if context:
                    # Only release to pool if it was acquired from pool
                    if not from_pool:
                        # For domain-specific contexts, just close them
                        try:
                            await context.close()
                        except:
                            pass
                    else:
                        await self.browser_pool.release(context)

    @retry_async(max_attempts=2, delay=3.0, exceptions=(ConnectionError, TimeoutError))
    async def _perform_sequence_analysis_workflow(self, url: str, sequence: List[Dict], auth_state: Dict = None):
        """执行完整的交互序列分析工作流"""
        context: Optional[BrowserContext] = None
        from_pool = False
        
        async with self.concurrency_semaphore:
            try:
                # 获取浏览器上下文
                if hasattr(self.browser_pool, 'create_context_for_domain'):
                    context = await self.retry_manager.execute(
                        self.browser_pool.create_context_for_domain,
                        url,
                        exceptions=(ConnectionError, TimeoutError, Exception)
                    )
                else:
                    context = await self.retry_manager.execute(
                        self.browser_pool.acquire,
                        exceptions=(ConnectionError, TimeoutError, Exception)
                    )
                    from_pool = True
                    
                page = await context.new_page()
                await self._setup_page_for_analysis(page)

                # 注入认证状态
                if auth_state:
                    await auth_tools.inject_auth_state(page, auth_state)
                    await auth_tools.inject_with_retry_on_navigation(page, auth_state)
                
                # 导航到目标页面
                await browser_tools.navigate(page, url)
                
                # 创建并配置交互复现器
                replayer = InteractionReplayer(page, {
                    'wait_after_action': 0.3,  # 较短的等待时间
                    'max_retries': 3
                })
                
                # 验证序列是否可以复现
                validator = InteractionValidator()
                validation_result = await validator.validate_sequence(sequence, page)
                
                if not validation_result['valid']:
                    self.logger.warning(f"交互序列验证失败: {validation_result['errors']}")
                
                # 复现交互序列
                self.logger.info("开始复现交互序列...")
                replay_success = await replayer.replay_sequence()
                
                if replay_success:
                    self.logger.info("交互序列复现成功，开始分析...")
                    
                    # 捕获网络数据
                    sniffer = NetworkSniffer()
                    await sniffer.start_capture(page)
                    
                    # 等待可能的网络请求完成
                    await asyncio.sleep(2)
                    await sniffer.stop_capture(page)
                    network_analysis = sniffer.analyze_api_calls()
                    
                    # 创建页面快照
                    snapshot = await self._create_interaction_snapshot(page, {
                        'url': url,
                        'interaction_type': 'sequence_replay',
                        'element_info': {}
                    })
                    
                    # 执行分析
                    analysis_results = await self._run_full_analysis(page, snapshot, {
                        'url': url,
                        'interaction_type': 'sequence_replay',
                        'element_info': {}
                    })
                    analysis_results['network_packet_analysis'] = network_analysis
                    analysis_results['sequence_validation'] = validation_result
                    analysis_results['replay_success'] = replay_success
                    
                    if self.enable_llm_analysis:
                        analysis_results['llm_analysis'] = await self._perform_llm_analysis(snapshot, {
                            'url': url,
                            'interaction_type': 'sequence_replay',
                            'element_info': {}
                        }, analysis_results)
                    
                    if self.generate_interaction_reports:
                        await self._accumulate_and_report({
                            'url': url,
                            'interaction_type': 'sequence_replay',
                            'element_info': {},
                            'timestamp': asyncio.get_event_loop().time()
                        }, snapshot, analysis_results)
                else:
                    self.logger.error("交互序列复现失败")
                    
            except Exception as e:
                self.logger.error(f"交互序列分析工作流发生错误: {e}", exc_info=True)
            finally:
                if context:
                    if not from_pool:
                        try:
                            await context.close()
                        except:
                            pass
                    else:
                        await self.browser_pool.release(context)

    async def _replay_single_interaction(self, page: Page, event: Dict[str, Any]):
        interaction_type = event.get('interaction_type')
        element_info = event.get('element_info', {})
        selector = element_info.get('selector')
        text_content = element_info.get('text')

        if not selector:
            return

        # --- 定位逻辑 ---
        locator = page.locator(selector)
        count = await locator.count()
        if count > 1 and text_content:
            self.logger.info(f"选择器 '{selector}' 匹配到 {count} 个元素，将使用文本 '{text_content}' 进行精确过滤。")
            locator = locator.filter(has_text=text_content)
            if await locator.count() > 1:
                locator = locator.first
        
        # --- 操作逻辑 ---
        try:
            # 步骤1: 尝试标准Playwright操作，它会进行可见性等严格检查
            self.logger.info(f"尝试标准Playwright操作: {interaction_type}")
            if interaction_type == 'click' or interaction_type == 'submit':
                await locator.click(timeout=5000) # 缩短超时，快速失败
            elif interaction_type == 'input':
                await locator.fill(element_info.get('text', 'aegis_replay'), timeout=5000)

        except PlaywrightError as e:
            # 步骤2: 如果标准操作失败，启动B计划：JavaScript强制点击
            self.logger.warning(f"标准操作失败 ({e.message.splitlines()[0]})。启动B计划：JavaScript强制点击。")
            try:
                if interaction_type == 'click' or interaction_type == 'submit':
                    # evaluate方法可以在元素上执行任意JS代码，element.click()可以无视可见性
                    await locator.evaluate("element => element.click()")
                elif interaction_type == 'input':
                    # 对于输入，JS操作会更复杂，这里暂时只处理点击
                    self.logger.error("JavaScript强制输入尚未实现。")
                    raise e # 如果是input失败，则重新抛出原始异常
            except Exception as js_e:
                self.logger.error(f"JavaScript强制点击也失败了: {js_e}")
                raise js_e # 抛出JS点击的异常
        
        # 在操作后短暂等待
        await asyncio.sleep(0.5)

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
        async with self.findings_lock:
            self.cumulative_findings.extend(new_findings)
            total_findings = len(self.cumulative_findings)
        self.logger.info(f"累积了 {len(new_findings)} 个新发现，总计 {total_findings} 个发现")
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
        if dast_results and dast_results.get('security_findings'):
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
        
        js_crypto_analysis = results.get('js_crypto_analysis')
        if js_crypto_analysis and js_crypto_analysis.get('findings'):
            for finding in js_crypto_analysis['findings']:
                std_finding = {
                    'vulnerability': finding.get('type', 'JS/Crypto Issue'),
                    'severity': finding.get('severity', 'Medium'),
                    'confidence': 'Medium',
                    'description': finding.get('description'),
                    'evidence': finding.get('evidence'),
                    'source': 'js_crypto_analysis'
                }
                all_findings.append(std_finding)

        for finding in all_findings:
            finding.update({
                'url': event.get('url'),
                'interaction_type': event.get('interaction_type', 'N/A'),
                'element_selector': snapshot.get('target_element', {}).get('selector')
            })
        return all_findings

    async def _output_cumulative_report(self):
        async with self.findings_lock:
            if not self.cumulative_findings:
                self.logger.info("暂无发现，跳过报告输出")
                return
            findings_to_report = self.cumulative_findings.copy()
            self.cumulative_findings = []
        
        async with self.history_lock:
            history_length = len(self.interaction_history)
        
        report_data = {
            'worker': 'InteractionWorker-Cumulative',
            'source_context': {
                'initiator_url': self.target_url,
                'mode': 'passive',
                'total_interactions_analyzed': history_length
            },
            'findings': findings_to_report,
            'timestamp': asyncio.get_event_loop().time()
        }
        await self.output_q.put(report_data)
        self.logger.info(f"已输出包含 {len(findings_to_report)} 个发现的累积报告。")

    async def _create_interaction_snapshot(self, page: Page, event: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info("创建交互点快照...")
        page_content = await page.content()
        
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
            "target_element": event.get('element_info', {}),
            "sast_results": sast_results,
            "interaction_type": event.get('interaction_type'),
            "timestamp": event.get('timestamp')
        }

    async def _perform_targeted_analysis(self, page: Page, snapshot: Dict[str, Any], event: Dict[str, Any]) -> Dict[str, Any]:
        analysis_results = {'sast_findings': snapshot['sast_results']}
        if self.analysis_depth == 'deep':
            async with self.iast_findings_lock:
                self.iast_findings.clear()
            results = await asyncio.gather(
                self._analyze_js_and_crypto(page), # 移除冗余参数
                self._run_shadow_browser_test(page, snapshot, event),
                return_exceptions=True
            )
            analysis_results['js_crypto_analysis'] = results[0] if not isinstance(results[0], Exception) else None
            analysis_results['shadow_browser_test_results'] = results[1] if not isinstance(results[1], Exception) else None
            async with self.iast_findings_lock:
                analysis_results['iast_findings'] = self.iast_findings.copy()
                self.iast_findings.clear()
        return analysis_results

    async def _analyze_js_and_crypto(self, page: Page) -> Optional[Dict[str, Any]]: # 移除冗余参数
        self.logger.info("开始主动分析JS加密函数...")
        try:
            crypto_info = await browser_tools.get_crypto_functions(page)
            self.logger.info(f"JS加密分析完成。")
            return json.loads(crypto_info)
        except Exception as e:
            self.logger.error(f"JS加密分析失败: {e}")
            return None

    async def _run_shadow_browser_test(self, page: Page, snapshot: Dict[str, Any], event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        findings = []
        # This is a placeholder for the full DAST engine
        # For now, we just run a simple SSTI check on input events
        target_selector = snapshot.get('target_element', {}).get('selector')
        if event.get('interaction_type') == 'input' and target_selector:
            try:
                ssti_payload = "{{7*7}}"
                await page.fill(target_selector, ssti_payload, timeout=15000)
                await page.press(target_selector, 'Enter')
                await asyncio.sleep(1)
                content = await page.content()
                if "49" in content and ssti_payload not in content:
                    findings.append({
                        'type': 'SSTI',
                        'severity': 'High',
                        'description': 'Input field seems vulnerable to SSTI.',
                        'payload': ssti_payload
                    })
            except Exception as e:
                self.logger.warning(f"SSTI影人浏览器测试失败: {e}")
        return {'security_findings': findings}

    async def _test_url_params(self, url: str, auth_state: Optional[Dict]):
        self.logger.info(f"开始对URL参数进行DAST测试: {url}")
        try:
            rules_file = os.path.join(os.path.dirname(__file__), '..', 'dast_payloads', 'url_param_tests.yaml')
            if not os.path.exists(rules_file):
                return

            with open(rules_file, 'r', encoding='utf-8') as f:
                rules = yaml.safe_load(f)

            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            if not query_params:
                return

            async with self.concurrency_semaphore:
                context = await self.browser_pool.acquire()
                try:
                    page = await context.new_page()
                    if auth_state:
                        await auth_tools.inject_auth_state(page, auth_state)

                    for param_name, param_values in query_params.items():
                        for rule in rules:
                            if param_name in rule.get('params', []):
                                self.logger.info(f"URL参数 '{param_name}' 匹配规则 '{rule.get('name')}'，准备测试...")
                                await self._execute_param_test(page, url, param_name, rule)
                finally:
                    await self.browser_pool.release(context)

        except Exception as e:
            self.logger.error(f"URL参数分析失败: {e}", exc_info=True)

    async def _execute_param_test(self, page: Page, base_url: str, param_name: str, rule: Dict):
        payload_file_path = os.path.join(os.path.dirname(__file__), '..', 'dast_payloads', rule['test_payload_file'])
        if not os.path.exists(payload_file_path):
            return

        with open(payload_file_path, 'r', encoding='utf-8') as f:
            payloads = yaml.safe_load(f)

        for payload in payloads:
            try:
                parsed_url = urlparse(base_url)
                query_params = parse_qs(parsed_url.query)
                query_params[param_name] = [payload['value']]
                
                new_query = urlencode(query_params, doseq=True)
                test_url = urlunparse((parsed_url.scheme, parsed_url.netloc, parsed_url.path, parsed_url.params, new_query, parsed_url.fragment))
                
                self.logger.debug(f"测试URL: {test_url}")
                await page.goto(test_url, wait_until='domcontentloaded')
                content = await page.content()

                if payload.get('expected') and payload['expected'] in content:
                    finding = {
                        'vulnerability': f"URL参数存在{payload.get('type', 'Vulnerability')}",
                        'severity': 'High',
                        'description': f"URL参数 '{param_name}' 在注入Payload '{payload['value']}' 后，响应中出现了预期结果 '{payload['expected']}'。",
                        'evidence': f"URL: {test_url}",
                        'source': 'dast_url_param_scan'
                    }
                    async with self.findings_lock:
                        self.cumulative_findings.append(self._standardize_findings({}, {"target_element":{}}, {'llm_analysis':None, 'shadow_browser_test_results':{'security_findings':[finding]}})[0])
                    self.logger.warning(f"高危发现: {finding['description']}")
                    break

            except Exception as e:
                self.logger.warning(f"执行参数 '{param_name}' 的Payload '{payload.get('name')}' 测试失败: {e}")

    async def _perform_llm_analysis(self, snapshot: Dict[str, Any], event: Dict[str, Any], results: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            level = self.config.get('llm_service', {}).get('reasoning_level', 'high')
            goal = "分析用户交互点的安全风险，提供针对性的安全建议"
            
            # 在这里加入诊断日志
            self.logger.info(f"准备LLM分析，当前可用的情报键: {list(results.keys())}")

            prompt = get_interaction_analysis_prompt(event.get('interaction_type'), snapshot, results, goal, level)
            llm_result = await self._call_llm(prompt)
            if 'error' in llm_result: return None
            return json.loads(llm_result['response'])
        except Exception as e:
            self.logger.error(f"LLM分析失败: {e}")
            return None

    @retry_async(max_attempts=3, delay=5.0, exceptions=(TimeoutError, ConnectionError, Exception))
    async def _call_llm(self, prompt: str) -> Dict[str, Any]:
        if not self.llm_client: 
            return {'error': 'LLM client not initialized'}
        
        try:
            cfg = self.config['llm_service']['api_config']
            messages = [
                {"role": "system", "content": "你是一位网络安全专家，擅长分析网页交互中的安全风险。"}, 
                {"role": "user", "content": prompt}
            ]
            
            # 使用更长的超时时间
            timeout = cfg.get('timeout', 300)
            response = await asyncio.wait_for(
                self.llm_client.chat.completions.create(
                    model=cfg['model_name'], 
                    messages=messages, 
                    max_tokens=1500, 
                    temperature=0.5
                ), 
                timeout=timeout
            )
            
            content = response.choices[0].message.content
            await log_ai_dialogue(
                prompt, 
                content, 
                self.config.get('logging', {}).get('ai_dialogues_file', './logs/ai_dialogues.jsonl')
            )
            return {'response': content}
            
        except asyncio.TimeoutError:
            self.logger.error(f"LLM调用超时（{timeout}秒）")
            return {'error': f'LLM call timeout after {timeout} seconds'}
        except Exception as e:
            self.logger.error(f"LLM调用失败: {e}")
            return {'error': str(e)}