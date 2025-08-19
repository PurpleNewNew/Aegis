import asyncio
import logging
import json
import os
from typing import Dict, Any, Optional
from openai import AsyncOpenAI
from playwright.async_api import Page, BrowserContext
from src.utils.browser_pool import BrowserPool
from src.tools import browser_tools, auth_tools
from src.sast_tools import secret_scanner, xss_scanner, crypto_detector
from src.prompts.prompt import get_interaction_analysis_prompt
from src.utils.ai_logger import log_ai_dialogue

class InteractionWorker:
    """
    无感被动交互分析器，只在用户进行页面交互操作时进行快照+分析。
    不进行自主决策，只对用户交互的功能点进行深入安全分析。
    """

    def __init__(self, config: dict, browser_pool: BrowserPool, concurrency_semaphore: asyncio.Semaphore, input_q, output_q, debug_events_q=None):
        self.config = config
        self.browser_pool = browser_pool
        self.concurrency_semaphore = concurrency_semaphore
        self.input_q = input_q
        self.output_q = output_q
        self.debug_events_q = debug_events_q
        self.logger = logging.getLogger(self.__class__.__name__)
        
        passive_config = config.get('investigation_manager', {}).get('passive_mode', {})
        self.analysis_depth = passive_config.get('analysis_depth', 'deep')
        self.auto_security_testing = passive_config.get('auto_security_testing', True)
        self.interaction_types = passive_config.get('interaction_types', ['click', 'submit', 'input'])
        self.analysis_timeout = passive_config.get('analysis_timeout', 60)
        self.generate_interaction_reports = passive_config.get('generate_interaction_reports', True)
        self.enable_llm_analysis = config.get('interaction_analysis', {}).get('enable_llm', True)
        
        self.max_parallel_interactions = self.concurrency_semaphore._value
        self.interaction_history = []
        self.cumulative_findings = []
        self.last_report_time = 0
        self.report_interval = 60
        self.target_url = None
        
        self.logger.info(f"InteractionWorker初始化完成，分析深度: {self.analysis_depth}, 交互类型: {self.interaction_types}")
        
        llm_config = self.config.get('llm_service', {})
        if llm_config and llm_config.get('api_config'):
            self.llm_client = AsyncOpenAI(
                base_url=llm_config['api_config'].get('base_url'),
                api_key=llm_config['api_config'].get('api_key')
            )
        else:
            self.llm_client = None
        
    async def analyze_interaction(self, interaction_event: Dict[str, Any]):
        if not self.auto_security_testing:
            return
        if interaction_event.get('interaction_type') not in self.interaction_types:
            return
        
        if not self.target_url:
            self.target_url = interaction_event.get('url')
        
        self.logger.info(f"接收到新的交互分析任务: {interaction_event.get('interaction_type')} on {interaction_event.get('url')}")
        asyncio.create_task(self.parallel_interaction_analysis(interaction_event))

    async def parallel_interaction_analysis(self, interaction_event: Dict[str, Any]):
        interaction_id = f"{interaction_event.get('timestamp', 0)}_{interaction_event.get('interaction_type')}_{hash(str(interaction_event.get('element_info', {})))}"
        context: BrowserContext | None = None
        
        async with self.concurrency_semaphore:
            self.logger.info(f"信号量已获取，开始执行交互分析 (ID: {interaction_id})。当前并发: {self.max_parallel_interactions - self.concurrency_semaphore._value}/{self.max_parallel_interactions}")
            try:
                context = await self.browser_pool.acquire()
                page = await context.new_page()

                await page.add_init_script(r"""(function() {
                    if (window.__aegis_hooked) return;
                    window.__aegis_hooked = true;
                    if (!window.__aegis_listeners) { window.__aegis_listeners = new WeakMap(); }
                    const originalAddEventListener = EventTarget.prototype.addEventListener;
                    EventTarget.prototype.addEventListener = function(type, listener, options) {
                        if (!window.__aegis_listeners.has(this)) { window.__aegis_listeners.set(this, []); }
                        window.__aegis_listeners.get(this).push({ type: type, listener: listener, useCapture: (typeof options === 'boolean') ? options : (options ? options.capture : false) });
                        return originalAddEventListener.call(this, type, listener, options);
                    };
                })();""")
                
                if interaction_event.get('auth_state'):
                    await auth_tools.inject_auth_state(page, interaction_event['auth_state'])
                
                await browser_tools.navigate(page, interaction_event['url'])
                
                interaction_snapshot = await self._create_interaction_snapshot(page, interaction_event)
                
                analysis_results = {'sast_findings': {}, 'interaction_specific_findings': [], 'llm_analysis': None}
                try:
                    analysis_results = await asyncio.wait_for(
                        self._perform_targeted_analysis(page, interaction_snapshot, interaction_event),
                        timeout=self.analysis_timeout
                    )
                except asyncio.TimeoutError:
                    self.logger.warning(f"交互分析超时（{self.analysis_timeout}秒），跳过深度分析")
                    analysis_results['sast_findings'] = interaction_snapshot['sast_results']
                
                if self.generate_interaction_reports:
                    await self._accumulate_and_report(interaction_event, interaction_snapshot, analysis_results)
                
                self.logger.info(f"交互分析任务成功完成 (ID: {interaction_id})")

            except Exception as e:
                self.logger.error(f"交互分析过程中发生错误 (ID: {interaction_id}): {e}", exc_info=True)
            finally:
                if context:
                    await self.browser_pool.release(context)

    async def _accumulate_and_report(self, interaction_event, snapshot, analysis_results):
        new_findings = self._standardize_findings(interaction_event, snapshot, analysis_results)
        self.cumulative_findings.extend(new_findings)
        self.logger.info(f"累积了 {len(new_findings)} 个新发现，总计 {len(self.cumulative_findings)} 个发现")

        current_time = interaction_event.get('timestamp', 0)
        if current_time - self.last_report_time >= self.report_interval:
            await self._output_cumulative_report()
            self.last_report_time = current_time
        else:
            self.logger.info(f"下次报告时间: {self.last_report_time + self.report_interval - current_time:.0f}秒后")

    def _standardize_findings(self, interaction_event, snapshot, analysis_results) -> list:
        all_findings = []
        if analysis_results.get('llm_analysis'):
            llm_res = analysis_results['llm_analysis']
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

        dast_results = analysis_results.get('shadow_browser_test_results', {})
        for test_type, findings in dast_results.items():
            if test_type == 'security_findings': continue
            for finding in findings:
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
                'url': interaction_event.get('url'),
                'interaction_type': interaction_event.get('interaction_type'),
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
        self.logger.info(f"已输出包含 {len(self.cumulative_findings)} 个发现的累积报告。")
        self.cumulative_findings = []

    async def _create_interaction_snapshot(self, page: Page, interaction_event: Dict[str, Any]) -> Dict[str, Any]:
        self.logger.info("创建交互点快照...")
        page_content = await browser_tools.get_web_content(page)
        all_interactive_elements = await browser_tools.get_interactive_elements(page)
        target_element = interaction_event.get('element_info', {})
        target_selector = target_element.get('selector')
        related_elements = self._find_related_elements(all_interactive_elements, target_element)
        form_data = interaction_event.get('form_data', {})
        if not form_data and interaction_event.get('interaction_type') == 'submit':
            form_data = await self._extract_form_data(page, target_selector)
        
        relevant_content = self._extract_relevant_content(page_content, related_elements)
        sast_results = {
            'secrets': secret_scanner.find_secrets(relevant_content),
            'xss_sinks': xss_scanner.find_xss_sinks(relevant_content),
            'crypto': crypto_detector.detect_crypto_patterns(relevant_content)
        }
        
        return {
            "url": page.url,
            "title": await page.title(),
            "target_element": target_element,
            "related_elements": related_elements,
            "form_data": form_data,
            "relevant_content_summary": relevant_content[:1000] + "..." if len(relevant_content) > 1000 else relevant_content,
            "sast_results": sast_results,
            "interaction_type": interaction_event.get('interaction_type'),
            "timestamp": interaction_event.get('timestamp')
        }

    def _find_related_elements(self, all_elements: list, target_element: Dict[str, Any]) -> list:
        related = []
        target_selector = target_element.get('selector')
        if not target_selector:
            return all_elements[:10]
        
        target_form = target_element.get('form')
        for elem in all_elements:
            if elem.get('form') == target_form:
                related.append(elem)
        
        if not related:
            for elem in all_elements:
                if elem.get('selector') != target_selector:
                    if self._are_selectors_adjacent(target_selector, elem.get('selector', '')):
                        related.append(elem)
                        if len(related) >= 5:
                            break
        
        if target_element not in related:
            related.insert(0, target_element)
        return related[:10]

    def _are_selectors_adjacent(self, selector1: str, selector2: str) -> bool:
        import re
        nums1 = re.findall(r'\d+', selector1)
        nums2 = re.findall(r'\d+', selector2)
        if nums1 and nums2:
            try:
                return abs(int(nums1[-1]) - int(nums2[-1])) <= 2
            except:
                return False
        return False

    async def _extract_form_data(self, page: Page, form_selector: str) -> Dict[str, Any]:
        try:
            if form_selector:
                return await page.evaluate("""(formSelector) => {
                    const form = document.querySelector(formSelector);
                    if (!form) return {};
                    const data = {};
                    const inputs = form.querySelectorAll('input, select, textarea');
                    inputs.forEach(input => {
                        if (input.name || input.id) {
                            const key = input.name || input.id;
                            data[key] = {
                                type: input.type,
                                value: input.value,
                                required: input.required,
                                placeholder: input.placeholder
                            };
                        }
                    });
                    return data;
                }""", form_selector)
        except Exception as e:
            self.logger.error(f"提取表单数据失败: {e}")
        return {}

    def _extract_relevant_content(self, page_content: str, related_elements: list) -> str:
        relevant_content = page_content
        for elem in related_elements:
            elem_id = elem.get('id')
            elem_name = elem.get('name')
            if elem_id and elem_id in page_content:
                import re
                pattern = f'.{{0,200}}{re.escape(elem_id)}.{{0,200}}'
                matches = re.findall(pattern, page_content, re.IGNORECASE)
                if matches:
                    relevant_content += '\n' + '\n'.join(matches)
            if elem_name and elem_name in page_content:
                import re
                pattern = f'.{{0,200}}{re.escape(elem_name)}.{{0,200}}'
                matches = re.findall(pattern, page_content, re.IGNORECASE)
                if matches:
                    relevant_content += '\n' + '\n'.join(matches)
        return relevant_content

    async def _perform_targeted_analysis(self, page: Page, snapshot: Dict[str, Any], interaction_event: Dict[str, Any]) -> Dict[str, Any]:
        analysis_results = {
            'sast_findings': snapshot['sast_results'],
            'interaction_specific_findings': [],
            'js_breakpoint_analysis': None,
            'network_packet_analysis': None,
            'shadow_browser_test_results': None,
            'llm_analysis': None
        }
        
        interaction_type = interaction_event.get('interaction_type')
        
        if self.analysis_depth == 'deep':
            analysis_results['js_breakpoint_analysis'] = await self._analyze_js_breakpoints(page, snapshot, interaction_event)
            analysis_results['network_packet_analysis'] = await self._analyze_network_packets(page, snapshot, interaction_event)
            analysis_results['shadow_browser_test_results'] = await self._run_shadow_browser_test(page, snapshot, interaction_event)
        
        if self.enable_llm_analysis and self.analysis_depth == 'deep':
            analysis_results['llm_analysis'] = await self._perform_llm_analysis(snapshot, interaction_event, analysis_results)
        
        return analysis_results

    async def _analyze_js_breakpoints(self, page: Page, snapshot: Dict[str, Any], interaction_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            self.logger.info("开始分析JavaScript函数断点...")
            target_selector = snapshot.get('target_element', {}).get('selector')
            if not target_selector: return None

            js_analysis = await page.evaluate(r"""(targetSelector) => {
                const target = document.querySelector(targetSelector);
                if (!target) return null;
                const analysis = { event_listeners: [], inline_handlers: [] };
                if (window.__aegis_listeners && window.__aegis_listeners.has(target)) {
                    window.__aegis_listeners.get(target).forEach(l => {
                        analysis.event_listeners.push({
                            type: l.type,
                            listener_code: l.listener.toString(),
                            useCapture: l.useCapture
                        });
                    });
                }
                const inlineEventTypes = ['onclick', 'onsubmit', 'onchange', 'oninput', 'onmouseover', 'onmouseout', 'onmousedown', 'onmouseup'];
                inlineEventTypes.forEach(eventType => {
                    if (target[eventType]) {
                        analysis.inline_handlers.push({
                            type: eventType,
                            handler_code: target[eventType].toString()
                        });
                    }
                });
                return analysis;
            }""", target_selector)
            
            if js_analysis:
                security_findings = []
                all_js_code = [h.get('handler_code', '') for h in js_analysis.get('inline_handlers', [])] + \
                              [l.get('listener_code', '') for l in js_analysis.get('event_listeners', [])]
                
                dangerous_functions = ['eval', 'innerHTML', 'outerHTML', 'document.write']
                for code_block in all_js_code:
                    for func in dangerous_functions:
                        if func in code_block:
                            security_findings.append({
                                'type': 'dangerous_js_function',
                                'severity': 'High',
                                'description': f'在事件处理器中检测到危险的JavaScript函数调用: {func}',
                                'context': code_block[:200]
                            })
                
                js_analysis['security_findings'] = security_findings
                self.logger.info(f"JS断点分析完成，发现 {len(security_findings)} 个潜在安全问题")
                return js_analysis
            return None
        except Exception as e:
            self.logger.error(f"JS断点分析失败: {e}", exc_info=True)
            return None

    async def _analyze_network_packets(self, page: Page, snapshot: Dict[str, Any], interaction_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            self.logger.info("开始分析网络数据包...")
            network_data = {'requests': [], 'responses': [], 'security_findings': []}
            
            async def capture_request(request):
                network_data['requests'].append({
                    'url': request.url, 'method': request.method, 'headers': dict(request.headers),
                    'resource_type': request.resource_type
                })
                if 'password' in request.url.lower() or 'token' in request.url.lower():
                    if not request.url.startswith('https://'):
                        network_data['security_findings'].append({
                            'type': 'sensitive_data_over_http', 'severity': 'High',
                            'description': '敏感数据通过HTTP传输', 'url': request.url
                        })
            
            page.on('request', capture_request)
            target_selector = snapshot.get('target_element', {}).get('selector')
            if target_selector:
                try:
                    await page.wait_for_timeout(100)
                    interaction_type = interaction_event.get('interaction_type')
                    if interaction_type == 'click' or interaction_type == 'submit':
                        await page.click(target_selector, timeout=5000)
                    elif interaction_type == 'input':
                        await page.fill(target_selector, 'test_input', timeout=5000)
                        await page.press(target_selector, 'Enter')
                    await page.wait_for_timeout(2000)
                except Exception as interaction_error:
                    self.logger.warning(f"模拟交互以捕获网络包失败: {interaction_error}")
            
            page.remove_listener('request', capture_request)
            self.logger.info(f"网络数据包分析完成，捕获 {len(network_data['requests'])} 个请求")
            return network_data
        except Exception as e:
            self.logger.error(f"网络数据包分析失败: {e}", exc_info=True)
            return None

    async def _run_shadow_browser_test(self, page: Page, snapshot: Dict[str, Any], interaction_event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            self.logger.info("开始影子浏览器安全测试...")
            shadow_page = await page.context.new_page()
            self.logger.info("在现有上下文中创建了新的影子测试页面。 সন")

            test_results = {
                'xss_test_results': [], 'csrf_test_results': [],
                'input_validation_results': [], 'ssti_test_results': [],
                'security_findings': []
            }
            try:
                if interaction_event.get('auth_state'):
                    await auth_tools.inject_auth_state(shadow_page, interaction_event['auth_state'])
                await browser_tools.navigate(shadow_page, snapshot['url'])
                target_selector = snapshot.get('target_element', {}).get('selector')
                if target_selector:
                    test_results['input_validation_results'] = await self._test_input_validation(shadow_page, target_selector, interaction_event)
                    test_results['ssti_test_results'] = await self._test_ssti_vulnerabilities(shadow_page, target_selector, interaction_event)
                    if interaction_event.get('interaction_type') == 'submit':
                        test_results['csrf_test_results'] = await self._test_csrf_vulnerabilities(shadow_page, target_selector, snapshot)
                
                all_findings = []
                for key, value in test_results.items():
                    if key != 'security_findings':
                        all_findings.extend(value)
                test_results['security_findings'] = all_findings
                self.logger.info(f"影子浏览器测试完成，发现 {len(all_findings)} 个安全问题")
            finally:
                if not shadow_page.is_closed():
                    await shadow_page.close()
            return test_results
        except Exception as e:
            self.logger.error(f"影子浏览器测试失败: {e}", exc_info=True)
            return None

    async def _test_input_validation(self, page: Page, target_selector: str, interaction_event: Dict[str, Any]) -> list:
        findings = []
        try:
            payload_file = os.path.join(os.path.dirname(__file__), '..', 'dast_payloads', 'generic_validation.json')
            if not os.path.exists(payload_file): return findings
            with open(payload_file, 'r', encoding='utf-8') as f:
                validation_payloads = json.load(f)
        except Exception as e:
            self.logger.error(f"加载或解析payload文件失败: {e}")
            return findings

        if interaction_event.get('interaction_type') == 'input':
            for payload in validation_payloads:
                try:
                    await page.goto(page.url)
                    await page.fill(target_selector, payload['value'])
                    await page.press(target_selector, 'Enter')
                    await page.wait_for_timeout(1000)
                    page_content = await page.content()
                    if 'error' in page_content.lower() or 'exception' in page_content.lower():
                        findings.append({
                            'type': f"{payload['type']}_vulnerability", 'severity': 'Medium',
                            'description': f"检测到可能的{payload['type']}漏洞，载荷: {payload['value']}",
                            'payload': payload['value']
                        })
                except Exception as test_error:
                    self.logger.debug(f"输入验证测试失败: {test_error}")
        return findings

    async def _test_ssti_vulnerabilities(self, page: Page, target_selector: str, interaction_event: Dict[str, Any]) -> list:
        findings = []
        try:
            payload_file = os.path.join(os.path.dirname(__file__), '..', 'dast_payloads', 'ssti.json')
            if not os.path.exists(payload_file): return findings
            with open(payload_file, 'r', encoding='utf-8') as f:
                ssti_payloads = json.load(f)
        except Exception as e:
            self.logger.error(f"加载或解析SSTI payload文件失败: {e}")
            return findings

        if interaction_event.get('interaction_type') == 'input':
            for payload in ssti_payloads:
                try:
                    await page.goto(page.url)
                    await page.fill(target_selector, payload['value'])
                    await page.press(target_selector, 'Enter')
                    await page.wait_for_timeout(1500)
                    page_content = await page.content()
                    if payload['expected'] in page_content:
                        findings.append({
                            'type': 'ssti_vulnerability', 'severity': 'High',
                            'description': f"检测到SSTI漏洞，模板引擎: {payload.get('type')}, 注入: {payload['value']} -> 响应包含: {payload['expected']}",
                            'payload': payload['value']
                        })
                        break
                except Exception as test_error:
                    self.logger.debug(f"SSTI测试失败: {test_error}")
        return findings

    async def _test_csrf_vulnerabilities(self, page: Page, target_selector: str, snapshot: Dict[str, Any]) -> list:
        findings = []
        try:
            form_data = snapshot.get('form_data', {})
            has_csrf_token = any('csrf' in key.lower() or 'token' in key.lower() for key in form_data.keys())
            if not has_csrf_token:
                findings.append({
                    'type': 'missing_csrf_token', 'severity': 'Medium',
                    'description': '表单缺少CSRF保护令牌', 'form_data': form_data
                })
        except Exception as e:
            self.logger.error(f"CSRF测试过程中发生错误: {e}")
        return findings

    async def _call_llm(self, prompt: str) -> Dict[str, Any]:
        if not self.llm_client:
            self.logger.error("LLM客户端未初始化，跳过调用")
            return {'error': 'LLM client not initialized'}
        try:
            llm_config = self.config['llm_service']['api_config']
            messages = [{'role': 'system', 'content': '你是一位网络安全专家，擅长分析网页交互中的安全风险。'}, {'role': 'user', 'content': prompt}]
            response = await asyncio.wait_for(
                self.llm_client.chat.completions.create(
                    model=llm_config['model_name'], messages=messages,
                    max_tokens=1500, temperature=0.5,
                ),
                timeout=llm_config.get('timeout', 300)
            )
            content = response.choices[0].message.content
            ai_log_file = self.config.get('logging', {}).get('ai_dialogues_file', './logs/ai_dialogues.jsonl')
            await log_ai_dialogue(prompt, content, ai_log_file)
            return {
                'response': content, 'model': llm_config['model_name'],
                'tokens_used': response.usage.total_tokens if response.usage else 0
            }
        except Exception as e:
            self.logger.error(f"LLM调用失败: {e}")
            return {'error': str(e)}

    async def _perform_llm_analysis(self, snapshot: Dict[str, Any], interaction_event: Dict[str, Any], analysis_results: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        try:
            prompt = get_interaction_analysis_prompt(
                interaction_type=interaction_event.get('interaction_type'),
                snapshot=snapshot,
                analysis_results=analysis_results,
                goal="分析用户交互点的安全风险，提供针对性的安全建议"
            )
            llm_result = await self._call_llm(prompt)
            if 'error' in llm_result:
                self.logger.warning(f"LLM分析返回错误: {llm_result['error']}")
                return None
            try:
                return json.loads(llm_result['response'])
            except json.JSONDecodeError:
                return {
                    'risk_assessment': 'Unknown', 'security_recommendations': [llm_result['response']],
                    'potential_attack_vectors': [], 'raw_response': llm_result['response']
                }
        except Exception as e:
            self.logger.error(f"LLM分析失败: {e}")
            return None

    async def run(self):
        self.logger.info("InteractionWorker 开始运行，等待交互事件...")
        try:
            while True:
                interaction_event = await self.input_q.get()
                if interaction_event is None:
                    self.logger.info("收到退出信号，停止运行")
                    break
                await self.analyze_interaction(interaction_event)
                self.input_q.task_done()
        except asyncio.CancelledError:
            self.logger.info("InteractionWorker 任务被取消")
        except Exception as e:
            self.logger.error(f"InteractionWorker 运行出错: {e}", exc_info=True)
        finally:
            self.logger.info("InteractionWorker 已停止运行")