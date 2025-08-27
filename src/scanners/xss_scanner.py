"""XSS漏洞扫描器
实现静态和动态XSS检测
"""

import re
import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from playwright.async_api import Page, Request, Response
from .base import SASTScanner, DASTScanner, Vulnerability, VulnerabilityType, SeverityLevel, ScanContext, ScanResult, AISASTScanner


class XSSStaticScanner(AISASTScanner):
    """(AI增强) 静态XSS漏洞扫描器"""
    
    @property
    def name(self) -> str:
        return "XSS静态扫描器(AI增强)"
        
    @property
    def description(self) -> str:
        return "通过模式匹配和AI分析检测源代码中潜在的XSS漏洞"
        
    @property
    def vuln_types(self) -> List[VulnerabilityType]:
        return [VulnerabilityType.XSS]

    @property
    def prompt_name(self) -> str:
        return "xss" # 对应 xss_prompts.py
        
    DANGEROUS_SINKS = [
        r'\.innerHTML\s*=',
        r'\.outerHTML\s*=',
        r'document\.write\s*\(',
        r'eval\s*\(',
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.sink_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.DANGEROUS_SINKS]
        
    async def scan(self, context: ScanContext) -> ScanResult:
        """执行静态XSS扫描，并由AI辅助分析"""
        vulnerabilities = []
        errors = []
        
        if not context.source_code:
            return ScanResult(self.scanner_id, [], ["未提供源代码"], 0)
            
        try:
            # 1. 传统静态分析
            for pattern in self.sink_patterns:
                for match in pattern.finditer(context.source_code):
                    line_num = context.source_code[:match.start()].count('\n') + 1
                    evidence = context.source_code.splitlines()[line_num-1].strip()
                    vuln = self.create_vulnerability(
                        vuln_type=VulnerabilityType.XSS,
                        name="潜在的XSS Sink点 (规则匹配)",
                        description=f"发现危险的XSS sink点: {match.group()}",
                        severity=SeverityLevel.MEDIUM,
                        confidence="medium",
                        location=f"{context.url}#(line:{line_num})",
                        evidence=evidence,
                        remediation="使用textContent代替innerHTML，或实施适当的输入验证和输出编码",
                        cwe_id="CWE-79"
                    )
                    vulnerabilities.append(vuln)
            
            # 2. AI辅助分析
            self.logger.info("开始对源代码进行AI辅助分析...")
            ai_context = {
                "code_snippet": context.source_code,
                "variables": {},
                "trigger": "static_analysis",
                "url": context.url
            }
            ai_result = await self.analyze_with_ai(ai_context)
            if ai_result and ai_result.get('vulnerability_detected'):
                ai_vuln = self.create_vulnerability(
                    vuln_type=VulnerabilityType.XSS,
                    name="潜在的XSS漏洞 (AI分析)",
                    description=ai_result.get('reasoning', 'AI检测到潜在的XSS漏洞'),
                    severity=SeverityLevel.HIGH if ai_result.get('confidence') == 'High' else SeverityLevel.MEDIUM,
                    confidence=ai_result.get('confidence', 'medium').lower(),
                    location=context.url,
                    evidence=f"Source: {ai_result.get('source')}, Sink: {ai_result.get('sink')}",
                    remediation="AI建议：请仔细审查从用户输入到危险Sink的完整数据流。",
                    metadata={"ai_analysis": ai_result}
                )
                vulnerabilities.append(ai_vuln)

        except Exception as e:
            errors.append(f"静态XSS扫描失败: {str(e)}")
            self.logger.error(f"静态XSS扫描失败: {e}", exc_info=True)
            
        return ScanResult(self.scanner_id, vulnerabilities, errors, 0)


class XSSDynamicScanner(DASTScanner):
    """动态XSS漏洞扫描器 (功能完整版)"""
    
    @property
    def name(self) -> str: return "XSS动态扫描器"
        
    @property
    def description(self) -> str: return "通过注入载荷并分析响应来测试XSS漏洞"
        
    @property
    def vuln_types(self) -> List[VulnerabilityType]: return [VulnerabilityType.XSS]
        
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.payloads = self.config.get('custom_payloads', self._get_default_payloads())
        self.test_params = self.config.get('test_params', True)
        self.test_headers = self.config.get('test_headers', True)
        
    def _get_default_payloads(self) -> List[Dict[str, Any]]:
        """获取要测试的XSS载荷"""
        return [
            {"payload": "<script>alert('XSS')</script>", "type": "script_tag"},
            {"payload": "<img src=x onerror=alert('XSS')>", "type": "img_event"},
            {"payload": "<svg onload=alert('XSS')>", "type": "svg_event"},
            {"payload": "javascript:alert('XSS')", "type": "javascript_uri"},
            {"payload": "<iframe src=javascript:alert('XSS')>", "type": "iframe"},
            {"payload": "'\">\"<script>alert(String.fromCharCode(88,83,83))</script>", "type": "polyglot"},
            {"payload": "'\">\"<img src=x onerror=alert(1)>", "type": "polyglot_img"},
            {"payload": "#<img src=x onerror=alert('XSS')>", "type": "dom_fragment"},
            {"payload": "?x=<script>alert('XSS')</script>", "type": "query_param"}
        ]
        
    async def scan(self, context: ScanContext) -> ScanResult:
        """执行动态XSS扫描"""
        vulnerabilities = []
        errors = []
        
        if not context.page:
            return ScanResult(self.scanner_id, [], ["未提供用于动态扫描的页面"], 0)
            
        try:
            if self.test_params and context.params:
                await self._test_parameters(context, vulnerabilities)
                
            if self.test_headers:
                await self._test_headers(context, vulnerabilities)
                
            await self._test_forms(context, vulnerabilities)
            
        except Exception as e:
            errors.append(f"动态XSS扫描失败: {str(e)}")
            
        return ScanResult(self.scanner_id, vulnerabilities, errors, 0)
        
    async def _test_parameters(self, context: ScanContext, vulnerabilities: List[Vulnerability]) -> None: 
        if not context.params: return
        base_url = context.url
        for param_name, param_value in context.params.items():
            for payload_info in self.payloads:
                try:
                    test_params = context.params.copy()
                    test_params[param_name] = payload_info["payload"]
                    parsed = urlparse(base_url)
                    query = urlencode(test_params)
                    test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, query, parsed.fragment))
                    await context.page.goto(test_url, wait_until="networkidle", timeout=5000)
                    if await self._check_payload_executed(context.page, payload_info["payload"]):
                        vuln = self.create_vulnerability(
                            vuln_type=VulnerabilityType.XSS, name=f"URL参数中的反射型XSS",
                            description=f"URL参数 '{param_name}' 易受XSS注入攻击",
                            severity=SeverityLevel.HIGH, confidence="high",
                            location=f"{context.url}?{param_name}=...)", evidence=f"载荷: {payload_info['payload']}",
                            remediation="对URL参数实施适当的输入验证和输出编码", cwe_id="CWE-79"
                        )
                        vulnerabilities.append(vuln)
                        break
                    await context.page.goto(base_url)
                except Exception as e:
                    self.logger.debug(f"测试参数 {param_name} 失败: {e}")
                    continue
                    
    async def _test_headers(self, context: ScanContext, vulnerabilities: List[Vulnerability]) -> None: 
        for payload_info in self.payloads:
            try:
                await context.page.set_extra_http_headers({"User-Agent": payload_info["payload"]})
                await context.page.reload(wait_until="networkidle")
                if await self._check_payload_executed(context.page, payload_info["payload"]):
                    vuln = self.create_vulnerability(
                        vuln_type=VulnerabilityType.XSS, name="User-Agent头中的XSS",
                        description="User-Agent头易受XSS注入攻击", severity=SeverityLevel.MEDIUM, confidence="medium",
                        location=context.url, evidence=f"User-Agent中的载荷: {payload_info['payload']}",
                        remediation="在显示前对User-Agent头值进行清理", cwe_id="CWE-79"
                    )
                    vulnerabilities.append(vuln)
                    break
            except Exception as e:
                self.logger.debug(f"测试User-Agent头失败: {e}")
                continue
                
    async def _test_forms(self, context: ScanContext, vulnerabilities: List[Vulnerability]) -> None: 
        try:
            forms = await context.page.query_selector_all("form")
            for form in forms:
                form_inputs = await form.query_selector_all("input[type='text'], input[type='search'], textarea")
                for input_field in form_inputs[:3]:
                    input_name = await input_field.get_attribute("name") or "unnamed"
                    for payload_info in self.payloads[:2]:
                        try:
                            await input_field.fill(payload_info["payload"])
                            await form.evaluate("form => form.submit()")
                            await context.page.wait_for_load_state("networkidle", timeout=5000)
                            if await self._check_payload_executed(context.page, payload_info["payload"]):
                                vuln = self.create_vulnerability(
                                    vuln_type=VulnerabilityType.XSS, name="表单输入中的存储型XSS",
                                    description=f"表单输入 '{input_name}' 易受存储型XSS攻击",
                                    severity=SeverityLevel.HIGH, confidence="high", location=context.url,
                                    evidence=f"载荷: {payload_info['payload']}",
                                    remediation="对表单输入实施适当的输入验证和输出编码", cwe_id="CWE-79"
                                )
                                vulnerabilities.append(vuln)
                            await context.page.go_back(wait_until="networkidle")
                        except Exception as e:
                            self.logger.debug(f"测试表单输入 {input_name} 失败: {e}")
                            continue
        except Exception as e:
            self.logger.debug(f"测试表单失败: {e}")
            
    async def _check_payload_executed(self, page: Page, payload: str) -> bool: 
        try:
            dialog_count = 0
            def handle_dialog(dialog):
                nonlocal dialog_count
                dialog_count += 1
                asyncio.create_task(dialog.dismiss())
            page.on("dialog", handle_dialog)
            await asyncio.sleep(0.5)
            page.remove_listener("dialog", handle_dialog)
            if dialog_count > 0: return True
            if "<script>" in payload:
                scripts = await page.query_selector_all("script")
                for script in scripts:
                    content = await script.text_content()
                    if content and "alert" in content: return True
            if "onerror=" in payload:
                elements = await page.query_selector_all("[onerror*='alert']")
                if elements: return True
            return False
        except Exception:
            return False