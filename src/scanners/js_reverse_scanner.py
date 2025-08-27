"""JavaScript逆向工程扫描器
分析JavaScript代码的安全问题和加密实现
"""

import re
import json
import asyncio
from typing import List, Dict, Any, Optional, Set
from urllib.parse import urlparse

from playwright.async_api import Page, Request, Response
from .base import SASTScanner, IASTScanner, Vulnerability, VulnerabilityType, SeverityLevel, ScanContext, ScanResult


class JSReverseScanner(SASTScanner, IASTScanner):
    """JavaScript逆向工程和分析扫描器"""
    
    @property
    def name(self) -> str:
        return "JS逆向扫描器"
        
    @property
    def description(self) -> str:
        return "分析JavaScript代码中的加密实现和安全问题"
        
    @property
    def vuln_types(self) -> List[VulnerabilityType]:
        return [VulnerabilityType.JS_REVERSE, VulnerabilityType.INSECURE_CRYPTO, VulnerabilityType.SECRET_LEAKAGE]
        
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        super().__init__(config)
        self.minify_threshold = self.config.get('minify_threshold', 0.8)
        self.max_file_size = self.config.get('max_file_size', 1024 * 1024)  # 1MB
        
        # 加密模式
        self.crypto_patterns = {
            'insecure_hash': [
                (r'MD5\s*\(', 'MD5已被破解'),
                (r'SHA1\s*\(', 'SHA1已被破解'),
                (r'hash\s*\(\s*[\'"]md5[\'"]', 'MD5哈希函数'),
                (r'hash\s*\(\s*[\'"]sha1[\'"]', 'SHA1哈希函数'),
            ],
            'hardcoded_key': [
                (r'key\s*[:=]\s*["\'][A-Za-z0-9+/=]{32,}["\']', '硬编码的加密密钥'),
                (r'secret\s*[:=]\s*["\'][A-Za-z0-9+/=]{16,}["\']', '硬编码的密钥'),
                (r'password\s*[:=]\s*["\'][^"\']{8,}["\']', '硬编码的密码'),
                (r'api_?key\s*[:=]\s*["\'][A-Za-z0-9_]{16,}["\']', '硬编码的API密钥'),
                (r'token\s*[:=]\s*["\'][A-Za-z0-9+/=]{20,}["\']', '硬编码的令牌'),
            ],
            'weak_crypto': [
                (r'crypto\.createCipher\s*\(', '使用createCipheriv代替'),
                (r'crypto\.createDecipher\s*\(', '使用createDecipheriv代替'),
                (r'RC4\s*\(', 'RC4不安全'),
                (r'DES\s*\(', 'DES不安全'),
                (r'3DES\s*\(', '3DES已弃用'),
                (r' ECB\s*\(', 'ECB模式不安全'),
            ],
            'random_issues': [
                (r'Math\.random\s*\(', 'Math.random()在密码学上不安全'),
                (r'crypto\.pseudoRandomBytes\s*\(', '使用randomBytes代替'),
            ],
            'obfuscation': [
                (r'eval\s*\(', '使用eval动态执行代码'),
                (r'Function\s*\(', '使用Function动态执行代码'),
                (r'setTimeout\s*\([^,]*,\s*[^0]', '带有字符串参数的setTimeout'),
                (r'setInterval\s*\([^,]*,\s*[^0]', '带有字符串参数的setInterval'),
                (r'new\s+Function\s*\(', '动态函数创建'),
                (r'document\.write\s*\(', '动态内容写入'),
            ],
        }
        
        # 编译所有模式
        self.compiled_patterns = {}
        for category, patterns in self.crypto_patterns.items():
            self.compiled_patterns[category] = [
                (re.compile(pattern, re.IGNORECASE), description)
                for pattern, description in patterns
            ]
            
    async def scan(self, context: ScanContext) -> ScanResult:
        """执行JS分析扫描"""
        vulnerabilities = []
        errors = []
        
        if not context.source_code and not context.page:
            return ScanResult(
                scanner_id=self.scanner_id,
                vulnerabilities=vulnerabilities,
                errors=["未提供源代码或页面"],
                execution_time=0
            )
            
        try:
            # 如果我们有页面，提取JS代码
            if context.page and not context.source_code:
                js_codes = await self._extract_js_code(context.page)
                js_code = "\n".join(js_codes.values())
                context.source_code = js_code
                
            if not context.source_code:
                return ScanResult(
                    scanner_id=self.scanner_id,
                    vulnerabilities=vulnerabilities,
                    errors=["未找到JavaScript代码"],
                    execution_time=0
                )
                
            # 检查文件大小
            if len(context.source_code) > self.max_file_size:
                errors.append(f"JS文件过大 ({len(context.source_code)} 字节)，跳过某些检查")
                
            # 分析JS代码
            vulnerabilities.extend(await self._analyze_crypto(context))
            vulnerabilities.extend(await self._analyze_obfuscation(context))
            vulnerabilities.extend(await self._analyze_secrets(context))
            
            # 如果我们有页面，执行运行时分析
            if context.page:
                vulnerabilities.extend(await self._runtime_analysis(context))
                
        except Exception as e:
            errors.append(f"JS逆向扫描失败: {str(e)}")
            
        return ScanResult(
            scanner_id=self.scanner_id,
            vulnerabilities=vulnerabilities,
            errors=errors,
            execution_time=0
        )
        
    async def _extract_js_code(self, page: Page) -> Dict[str, str]:
        """从页面提取JavaScript代码"""
        js_codes = {}
        
        try:
            # 获取内联脚本
            scripts = await page.query_selector_all("script")
            for i, script in enumerate(scripts):
                content = await script.text_content()
                src = await script.get_attribute("src")
                
                if content and len(content.strip()) > 10:
                    if src:
                        js_codes[src] = content
                    else:
                        js_codes[f"inline_script_{i}"] = content
                        
            # 获取外部脚本
            external_scripts = await page.evaluate("""
                () => {
                    const scripts = [];
                    document.querySelectorAll('script[src]').forEach(script => {
                        scripts.push(script.src);
                    });
                    return scripts;
                }
            """)
            
            # 注意：在实际实现中，您可能想要获取外部脚本
            # 现在，我们只记录它们的存在
            for src in external_scripts:
                js_codes[src] = f"// 外部脚本: {src}\n// 内容未分析"
                
        except Exception as e:
            self.logger.debug(f"提取JS代码失败: {e}")
            
        return js_codes
        
    async def _analyze_crypto(self, context: ScanContext) -> List[Vulnerability]:
        """分析加密实现"""
        vulnerabilities = []
        
        if not context.source_code:
            return vulnerabilities
            
        # 检查不安全的加密模式
        for category, patterns in self.compiled_patterns.items():
            if category in ['insecure_hash', 'weak_crypto', 'random_issues']:
                for pattern, description in patterns:
                    for match in pattern.finditer(context.source_code):
                        line_num = self._get_line_number(context.source_code, match.start())
                        line_content = self._get_line_content(context.source_code, match.start())
                        
                        # 确定严重性
                        if category == 'insecure_hash':
                            severity = SeverityLevel.MEDIUM
                        elif category == 'weak_crypto':
                            severity = SeverityLevel.HIGH
                        else:  # random_issues
                            severity = SeverityLevel.MEDIUM
                            
                        vuln = self.create_vulnerability(
                            vuln_type=VulnerabilityType.INSECURE_CRYPTO,
                            name=f"不安全的加密实现: {description}",
                            description=f"在第 {line_num} 行发现 {description}",
                            severity=severity,
                            confidence="high",
                            location=f"{context.url}#L{line_num}",
                            evidence=line_content.strip(),
                            remediation=self._get_crypto_remediation(category, description),
                            cwe_id=self._get_crypto_cwe(category)
                        )
                        vulnerabilities.append(vuln)
                        
        return vulnerabilities
        
    async def _analyze_obfuscation(self, context: ScanContext) -> List[Vulnerability]:
        """分析代码混淆和潜在后门"""
        vulnerabilities = []
        
        if not context.source_code:
            return vulnerabilities
            
        # 检查混淆模式
        for pattern, description in self.compiled_patterns['obfuscation']:
            for match in pattern.finditer(context.source_code):
                line_num = self._get_line_number(context.source_code, match.start())
                line_content = self._get_line_content(context.source_code, match.start())
                
                # 检查是否已压缩
                if self._is_minified(line_content):
                    severity = SeverityLevel.MEDIUM
                    confidence = "low"
                else:
                    severity = SeverityLevel.HIGH
                    confidence = "high"
                    
                vuln = self.create_vulnerability(
                    vuln_type=VulnerabilityType.JS_REVERSE,
                    name=f"代码混淆: {description}",
                    description=f"发现 {description}，可能表示混淆代码或潜在后门",
                    severity=severity,
                    confidence=confidence,
                    location=f"{context.url}#L{line_num}",
                    evidence=line_content.strip(),
                    remediation="避免动态代码执行。检查代码中是否存在恶意内容。",
                    cwe_id="CWE-94"
                )
                vulnerabilities.append(vuln)
                
        # 检查其他混淆指标
        obfuscation_indicators = [
            (r'\\x[0-9a-f]{2}', '十六进制编码'),
            (r'\\u[0-9a-f]{4}', 'Unicode编码'),
            (r'\\[0-7]{1,3}', '八进制编码'),
            (r'\[\]\["filter"\]["constructor"\]\("return this"\)\(\)', '混淆代码构造'),
            (r'atob\s*\(', 'Base64解码'),
            (r'btoa\s*\(', 'Base64编码'),
        ]
        
        for pattern, desc in obfuscation_indicators:
            compiled = re.compile(pattern, re.IGNORECASE)
            matches = list(compiled.finditer(context.source_code))
            
            # 如果匹配很多，可能是混淆的
            if len(matches) > 5:
                vuln = self.create_vulnerability(
                    vuln_type=VulnerabilityType.JS_REVERSE,
                    name="潜在代码混淆",
                    description=f"发现 {len(matches)} 个 {desc} 实例，表明代码可能被混淆",
                    severity=SeverityLevel.MEDIUM,
                    confidence="medium",
                    location=context.url,
                    evidence=f"发现多个 {desc} 模式",
                    remediation="检查混淆代码。考虑使用反混淆工具。",
                    cwe_id="CWE-506"
                )
                vulnerabilities.append(vuln)
                
        return vulnerabilities
        
    async def _analyze_secrets(self, context: ScanContext) -> List[Vulnerability]:
        """分析硬编码密钥"""
        vulnerabilities = []
        
        if not context.source_code:
            return vulnerabilities
            
        # 检查硬编码密钥
        for pattern, description in self.compiled_patterns['hardcoded_key']:
            for match in pattern.finditer(context.source_code):
                line_num = self._get_line_number(context.source_code, match.start())
                line_content = self._get_line_content(context.source_code, match.start())
                
                # 提取实际密钥（已脱敏）
                secret_value = match.group()
                masked_secret = secret_value[:8] + "*" * (len(secret_value) - 12) + secret_value[-4:] if len(secret_value) > 12 else "*" * len(secret_value)
                
                vuln = self.create_vulnerability(
                    vuln_type=VulnerabilityType.SECRET_LEAKAGE,
                    name=f"硬编码密钥: {description}",
                    description=f"在JavaScript代码中发现硬编码密钥",
                    severity=SeverityLevel.HIGH,
                    confidence="high",
                    location=f"{context.url}#L{line_num}",
                    evidence=f"行: {line_content.strip().replace(secret_value, masked_secret)}",
                    remediation="移除硬编码密钥。使用环境变量或安全的密钥管理。",
                    cwe_id="CWE-798"
                )
                vulnerabilities.append(vuln)
                
        # 检查其他密钥模式
        secret_patterns = [
            (r'api[_-]?key\s*[:=]\s*["\'][A-Za-z0-9]{20,}["\']', 'API密钥'),
            (r'access[_-]?token\s*[:=]\s*["\'][A-Za-z0-9+/=]{20,}["\']', '访问令牌'),
            (r'client[_-]?secret\s*[:=]\s*["\'][A-Za-z0-9+/=]{20,}["\']', '客户端密钥'),
            (r'auth[_-]?token\s*[:=]\s*["\'][A-Za-z0-9+/=]{20,}["\']', '认证令牌'),
            (r'bearer\s+["\'][A-Za-z0-9+/=]{20,}["\']', 'Bearer令牌'),
        ]
        
        for pattern, desc in secret_patterns:
            compiled = re.compile(pattern, re.IGNORECASE)
            for match in compiled.finditer(context.source_code):
                line_num = self._get_line_number(context.source_code, match.start())
                line_content = self._get_line_content(context.source_code, match.start())
                
                vuln = self.create_vulnerability(
                    vuln_type=VulnerabilityType.SECRET_LEAKAGE,
                    name=f"潜在密钥泄露",
                    description=f"在JavaScript代码中发现潜在的 {desc}",
                    severity=SeverityLevel.HIGH,
                    confidence="medium",
                    location=f"{context.url}#L{line_num}",
                    evidence=line_content.strip(),
                    remediation="检查并移除任何硬编码凭证。使用安全的密钥管理。",
                    cwe_id="CWE-798"
                )
                vulnerabilities.append(vuln)
                
        return vulnerabilities
        
    async def _runtime_analysis(self, context: ScanContext) -> List[Vulnerability]:
        """执行运行时JavaScript分析"""
        vulnerabilities = []
        
        try:
            # 钩子控制台方法以检测敏感数据
            await context.page.add_init_script("""
                // 钩子控制台方法
                const originalConsoleLog = console.log;
                const originalConsoleError = console.error;
                const originalConsoleInfo = console.info;
                
                const sensitivePatterns = [
                    /password/i,
                    /secret/i,
                    /key/i,
                    /token/i,
                    /api[_-]?key/i,
                    /auth/i,
                    /credential/i,
                    /session/i,
                    /cookie/i
                ];
                
                function checkSensitiveData(data) {
                    const str = typeof data === 'string' ? data : JSON.stringify(data);
                    for (const pattern of sensitivePatterns) {
                        if (pattern.test(str)) {
                            return true;
                        }
                    }
                    return false;
                }
                
                console.log = function(...args) {
                    if (args.some(arg => checkSensitiveData(arg))) {
                        window.__sensitiveConsoleLog = window.__sensitiveConsoleLog || [];
                        window.__sensitiveConsoleLog.push({
                            type: 'log',
                            args: args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)),
                            timestamp: Date.now()
                        });
                    }
                    originalConsoleLog.apply(console, args);
                };
                
                console.error = function(...args) {
                    if (args.some(arg => checkSensitiveData(arg))) {
                        window.__sensitiveConsoleLog = window.__sensitiveConsoleLog || [];
                        window.__sensitiveConsoleLog.push({
                            type: 'error',
                            args: args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)),
                            timestamp: Date.now()
                        });
                    }
                    originalConsoleError.apply(console, args);
                };
                
                console.info = function(...args) {
                    if (args.some(arg => checkSensitiveData(arg))) {
                        window.__sensitiveConsoleLog = window.__sensitiveConsoleLog || [];
                        window.__sensitiveConsoleLog.push({
                            type: 'info',
                            args: args.map(arg => typeof arg === 'object' ? JSON.stringify(arg) : String(arg)),
                            timestamp: Date.now()
                        });
                    }
                    originalConsoleInfo.apply(console, args);
                };
            """)
            
            # 等待控制台输出
            await asyncio.sleep(2)
            
            # 检查敏感的控制台日志
            sensitive_logs = await context.page.evaluate("""
                () => window.__sensitiveConsoleLog || []
            """)
            
            if sensitive_logs:
                vuln = self.create_vulnerability(
                    vuln_type=VulnerabilityType.SECRET_LEAKAGE,
                    name="控制台日志中的敏感数据",
                    description=f"在控制台日志中发现 {len(sensitive_logs)} 个敏感数据实例",
                    severity=SeverityLevel.MEDIUM,
                    confidence="high",
                    location=context.url,
                    evidence=json.dumps(sensitive_logs[:3], indent=2),  // 显示前3个
                    remediation="在生产代码中移除控制台日志中的敏感数据",
                    cwe_id="CWE-532"
                )
                vulnerabilities.append(vuln)
                
        except Exception as e:
            self.logger.debug(f"运行时分析失败: {e}")
            
        return vulnerabilities
        
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
        
    def _is_minified(self, line: str) -> bool:
        """检查行是否被压缩"""
        # 移除空白
        stripped = line.strip()
        if not stripped:
            return False
            
        # 检查相对于长度的空格/换行符数量
        space_ratio = (stripped.count(' ') + stripped.count('\t')) / len(stripped)
        return space_ratio < self.minify_threshold
        
    def _get_crypto_remediation(self, category: str, description: str) -> str:
        """获取加密问题的修复建议"""
        remediations = {
            'insecure_hash': "使用SHA-256或更强的哈希函数",
            'weak_crypto': "使用AES-256-GCM或其他现代加密算法",
            'random_issues': "使用crypto.randomBytes()生成密码学安全的随机数"
        }
        return remediations.get(category, "检查并更新加密实现")
        
    def _get_crypto_cwe(self, category: str) -> str:
        """获取加密问题的CWE ID"""
        cwes = {
            'insecure_hash': "CWE-328",
            'weak_crypto': "CWE-327",
            'random_issues': "CWE-338"
        }
        return cwes.get(category, "CWE-327")


# 注册扫描器
from .base import registry
registry.register(JSReverseScanner)