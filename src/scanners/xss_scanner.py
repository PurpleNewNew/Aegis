"""XSS漏洞扫描器
实现静态和动态XSS检测
"""

import re
import asyncio
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs

from playwright.async_api import Page, Request, Response
from .base import SASTScanner, DASTScanner, Vulnerability, VulnerabilityType, SeverityLevel, ScanContext, ScanResult


class XSSStaticScanner(SASTScanner):
    """静态XSS漏洞扫描器"""
    
    @property
    def name(self) -> str:
        return "XSS静态扫描器"
        
    @property
    def description(self) -> str:
        return "通过模式匹配检测源代码中潜在的XSS漏洞"
        
    @property
    def vuln_types(self) -> List[VulnerabilityType]:
        return [VulnerabilityType.XSS]
        
    # XSS模式
    DANGEROUS_SINKS = [
        r'\.innerHTML\s*=',
        r'\.outerHTML\s*=',
        r'document\.write\s*\(',
        r'document\.writeln\s*\(',
        r'eval\s*\(',
        r'setTimeout\s*\(\s*["\'][^"\']*["\']',
        r'setInterval\s*\(\s*["\'][^"\']*["\']',
        r'location\.href\s*=\s*["\']?javascript:',
        r'\.insertAdjacentHTML\s*\(',
        r'\.createContextualFragment\s*\(',
    ]
    
    CONTEXT_PATTERNS = [
        (r'<script[^>]*>.*?</script>', '脚本块'),
        (r'on\w+\s*=', '事件处理器'),
        (r'<[^>]*\bon\w+\s*=', '内联事件处理器'),
        (r'javascript:', 'JavaScript伪协议'),
        (r'<[^>]*\s*href\s*=\s*["\'][^"\']*javascript:', 'href中的JavaScript'),
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.sink_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in self.DANGEROUS_SINKS]
        self.context_patterns = [(re.compile(pattern, re.IGNORECASE | re.DOTALL), desc) 
                               for pattern, desc in self.CONTEXT_PATTERNS]
        
    async def scan(self, context: ScanContext) -> ScanResult:
        """执行静态XSS扫描"""
        vulnerabilities = []
        errors = []
        
        if not context.source_code:
            return ScanResult(
                scanner_id=self.scanner_id,
                vulnerabilities=vulnerabilities,
                errors=["未提供源代码"],
                execution_time=0
            )
            
        try:
            # 检查危险的sink点
            for pattern in self.sink_patterns:
                for match in pattern.finditer(context.source_code):
                    line_num = self._get_line_number(context.source_code, match.start())
                    line_content = self._get_line_content(context.source_code, match.start())
                    
                    # 检查用户输入是否能到达这个sink点
                    if self._check_user_input_reaches_sink(context.source_code, match.start()):
                        vuln = self.create_vulnerability(
                            vuln_type=VulnerabilityType.XSS,
                            name="潜在的XSS Sink点",
                            description=f"发现危险的XSS sink点: {match.group()}",
                            severity=SeverityLevel.HIGH,
                            confidence="medium",
                            location=f"{context.url}#{line_num}",
                            evidence=line_content.strip(),
                            remediation="使用textContent代替innerHTML，或实施适当的输入验证和输出编码",
                            cwe_id="CWE-79"
                        )
                        vulnerabilities.append(vuln)
                        
            # 检查危险的上下文
            for pattern, context_type in self.context_patterns:
                for match in pattern.finditer(context.source_code):
                    line_num = self._get_line_number(context.source_code, match.start())
                    line_content = self._get_line_content(context.source_code, match.start())
                    
                    vuln = self.create_vulnerability(
                        vuln_type=VulnerabilityType.XSS,
                        name=f"{context_type}中的XSS",
                        description=f"在{context_type}中发现潜在的可执行内容",
                        severity=SeverityLevel.MEDIUM,
                        confidence="low",
                        location=f"{context.url}#{line_num}",
                        evidence=line_content.strip(),
                        remediation="避免动态代码执行。使用安全的替代方案并对所有输入进行清理。"
                    )
                    vulnerabilities.append(vuln)
                    
        except Exception as e:
            errors.append(f"静态XSS扫描失败: {str(e)}")
            
        return ScanResult(
            scanner_id=self.scanner_id,
            vulnerabilities=vulnerabilities,
            errors=errors,
            execution_time=0
        )
        
    def _get_line_number(self, text: str, pos: int) -> int:
        """获取位置对应的行号"""
        return text[:pos].count('\n') + 1
        
    def _get_line_content(self, text: str, pos: int) -> str:
        """获取位置对应的行内容"""
        start = text.rfind('\n', 0, pos) + 1
        end = text.find('\n', pos)
        if end == -1:
            end = len(text)
        return text[start:end]
        
    def _check_user_input_reaches_sink(self, source_code: str, sink_pos: int) -> bool:
        """简单的启发式检查，判断用户输入是否能到达sink点"""
        # 在sink点之前查找常见的用户输入源
        input_sources = [
            r'location\.',
            r'document\.URL',
            r'document\.documentURI',
            r'document\.URLUnencoded',
            r'document\.cookie',
            r'referrer',
            r'window\.name',
            r'postMessage',
            r'localStorage',
            r'sessionStorage',
            r'getParameter',
            r'QueryString',
            r'Request\.Form',
            r'Request\.QueryString',
        ]
        
        # 获取sink点之前的代码
        code_before = source_code[:sink_pos]
        
        # 检查是否有输入源出现在sink点之前
        for source in input_sources:
            if re.search(source, code_before, re.IGNORECASE):
                return True
                
        return False


class XSSDynamicScanner(DASTScanner):
    """动态XSS漏洞扫描器"""
    
    @property
    def name(self) -> str:
        return "XSS动态扫描器"
        
    @property
    def description(self) -> str:
        return "通过注入载荷并分析响应来测试XSS漏洞"
        
    @property
    def vuln_types(self) -> List[VulnerabilityType]:
        return [VulnerabilityType.XSS]
        
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.payloads = self._get_payloads()
        self.test_params = self.config.get('test_params', True)
        self.test_headers = self.config.get('test_headers', True)
        
    def _get_payloads(self) -> List[Dict[str, Any]]:
        """获取要测试的XSS载荷"""
        return [
            # 基础XSS载荷
            {"payload": "<script>alert('XSS')</script>", "type": "script_tag"},
            {"payload": "<img src=x onerror=alert('XSS')>", "type": "img_event"},
            {"payload": "<svg onload=alert('XSS')>", "type": "svg_event"},
            {"payload": "javascript:alert('XSS')", "type": "javascript_uri"},
            {"payload": "<iframe src=javascript:alert('XSS')>", "type": "iframe"},
            
            # 多语言载荷
            {"payload": "'\"><script>alert(String.fromCharCode(88,83,83))</script>", "type": "polyglot"},
            {"payload": "'\"><img src=x onerror=alert(1)>", "type": "polyglot_img"},
            
            # 基于DOM的XSS
            {"payload": "#<img src=x onerror=alert('XSS')>", "type": "dom_fragment"},
            {"payload": "?x=<script>alert('XSS')</script>", "type": "query_param"},
        ]
        
    async def scan(self, context: ScanContext) -> ScanResult:
        """执行动态XSS扫描"""
        vulnerabilities = []
        errors = []
        
        if not context.page:
            return ScanResult(
                scanner_id=self.scanner_id,
                vulnerabilities=vulnerabilities,
                errors=["未提供用于动态扫描的页面"],
                execution_time=0
            )
            
        try:
            # 测试URL参数
            if self.test_params and context.params:
                await self._test_parameters(context, vulnerabilities)
                
            # 测试请求头
            if self.test_headers:
                await self._test_headers(context, vulnerabilities)
                
            # 测试表单输入
            await self._test_forms(context, vulnerabilities)
            
        except Exception as e:
            errors.append(f"动态XSS扫描失败: {str(e)}")
            
        return ScanResult(
            scanner_id=self.scanner_id,
            vulnerabilities=vulnerabilities,
            errors=errors,
            execution_time=0
        )
        
    async def _test_parameters(self, context: ScanContext, vulnerabilities: List[Vulnerability]) -> None:
        """测试URL参数中的XSS"""
        if not context.params:
            return
            
        base_url = context.url
        
        for param_name, param_value in context.params.items():
            for payload_info in self.payloads:
                try:
                    # 创建测试URL
                    test_params = context.params.copy()
                    test_params[param_name] = payload_info["payload"]
                    
                    # 构建带载荷的URL
                    from urllib.parse import urlencode, urlparse, urlunparse
                    parsed = urlparse(base_url)
                    query = urlencode(test_params)
                    test_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        query,
                        parsed.fragment
                    ))
                    
                    # 导航到测试URL
                    response = await context.page.goto(test_url, wait_until="networkidle", timeout=5000)
                    
                    # 检查载荷是否执行
                    if await self._check_payload_executed(context.page, payload_info["payload"]):
                        vuln = self.create_vulnerability(
                            vuln_type=VulnerabilityType.XSS,
                            name=f"URL参数中的反射型XSS",
                            description=f"URL参数 '{param_name}' 易受XSS注入攻击",
                            severity=SeverityLevel.HIGH,
                            confidence="high",
                            location=f"{context.url}?{param_name}=...)",
                            evidence=f"载荷: {payload_info['payload']}",
                            remediation="对URL参数实施适当的输入验证和输出编码",
                            cwe_id="CWE-79"
                        )
                        vulnerabilities.append(vuln)
                        break  # 每个参数一个漏洞就足够了
                        
                    # 返回原始URL
                    await context.page.goto(base_url)
                    
                except Exception as e:
                    self.logger.debug(f"测试参数 {param_name} 失败: {e}")
                    continue
                    
    async def _test_headers(self, context: ScanContext, vulnerabilities: List[Vulnerability]) -> None:
        """测试HTTP头中的XSS"""
        # 测试User-Agent头
        for payload_info in self.payloads:
            try:
                # 设置带有载荷的自定义User-Agent
                await context.page.set_extra_http_headers({
                    "User-Agent": payload_info["payload"]
                })
                
                # 刷新页面
                await context.page.reload(wait_until="networkidle")
                
                # 检查载荷是否执行
                if await self._check_payload_executed(context.page, payload_info["payload"]):
                    vuln = self.create_vulnerability(
                        vuln_type=VulnerabilityType.XSS,
                        name="User-Agent头中的XSS",
                        description="User-Agent头易受XSS注入攻击",
                        severity=SeverityLevel.MEDIUM,
                        confidence="medium",
                        location=context.url,
                        evidence=f"User-Agent中的载荷: {payload_info['payload']}",
                        remediation="在显示前对User-Agent头值进行清理",
                        cwe_id="CWE-79"
                    )
                    vulnerabilities.append(vuln)
                    break
                    
            except Exception as e:
                self.logger.debug(f"测试User-Agent头失败: {e}")
                continue
                
    async def _test_forms(self, context: ScanContext, vulnerabilities: List[Vulnerability]) -> None:
        """测试表单输入中的XSS"""
        try:
            # 查找页面上的所有表单
            forms = await context.page.query_selector_all("form")
            
            for form in forms:
                form_inputs = await form.query_selector_all("input[type='text'], input[type='search'], textarea")
                
                for input_field in form_inputs[:3]:  # 限制每个表单前3个输入
                    input_name = await input_field.get_attribute("name") or "unnamed"
                    
                    for payload_info in self.payloads[:2]:  # 限制每个输入的载荷
                        try:
                            # 用载荷填充表单
                            await input_field.fill(payload_info["payload"])
                            
                            # 提交表单
                            await form.evaluate("form => form.submit()")
                            
                            # 等待导航
                            await context.page.wait_for_load_state("networkidle", timeout=5000)
                            
                            # 检查载荷是否执行
                            if await self._check_payload_executed(context.page, payload_info["payload"]):
                                vuln = self.create_vulnerability(
                                    vuln_type=VulnerabilityType.XSS,
                                    name="表单输入中的存储型XSS",
                                    description=f"表单输入 '{input_name}' 易受存储型XSS攻击",
                                    severity=SeverityLevel.HIGH,
                                    confidence="high",
                                    location=context.url,
                                    evidence=f"载荷: {payload_info['payload']}",
                                    remediation="对表单输入实施适当的输入验证和输出编码",
                                    cwe_id="CWE-79"
                                )
                                vulnerabilities.append(vuln)
                                
                            # 返回
                            await context.page.go_back(wait_until="networkidle")
                            
                        except Exception as e:
                            self.logger.debug(f"测试表单输入 {input_name} 失败: {e}")
                            continue
                            
        except Exception as e:
            self.logger.debug(f"测试表单失败: {e}")
            
    async def _check_payload_executed(self, page: Page, payload: str) -> bool:
        """检查XSS载荷是否被执行"""
        try:
            # 检查警告对话框
            dialog_count = 0
            
            def handle_dialog(dialog):
                nonlocal dialog_count
                dialog_count += 1
                asyncio.create_task(dialog.dismiss())
                
            page.on("dialog", handle_dialog)
            
            # 等待任何对话框
            await asyncio.sleep(0.5)
            
            # 移除对话框处理器
            page.remove_listener("dialog", handle_dialog)
            
            if dialog_count > 0:
                return True
                
            # 检查载荷是否出现在DOM中
            if "<script>" in payload:
                scripts = await page.query_selector_all("script")
                for script in scripts:
                    content = await script.text_content()
                    if content and "alert" in content:
                        return True
                        
            # 检查注入的元素
            if "onerror=" in payload:
                elements = await page.query_selector_all("[onerror*='alert']")
                if elements:
                    return True
                    
            return False
            
        except Exception:
            return False


# 注册扫描器
from .base import registry
registry.register(XSSStaticScanner)
registry.register(XSSDynamicScanner)