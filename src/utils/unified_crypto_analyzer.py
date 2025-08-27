import re
import hashlib
import time
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from functools import lru_cache

@dataclass
class CryptoFinding:
    """统一的加密分析结果"""
    type: str  # 'algorithm', 'key', 'function', 'vulnerability'
    subtype: str  # 具体类型，如 'AES', 'hardcoded_key' 等
    name: str
    description: str
    severity: str  # 'Critical', 'High', 'Medium', 'Low'
    confidence: float  # 0.0-1.0
    evidence: str
    location: Dict[str, Any]  # 位置信息
    recommendations: List[str]
    analysis_method: str  # 'static', 'dynamic', 'ai'

class UnifiedCryptoAnalyzer:
    """统一的加密分析服务，整合所有加密分析功能"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.js_reverse_config = config.get('js_reverse', {})
        
        # 统一的加密模式配置
        self.crypto_patterns = self._load_crypto_patterns()
        
        # 缓存机制
        self.analysis_cache = {}
        self.cache_ttl = 3600  # 1小时
        
        # 从原有的模块导入功能
        from src.utils.crypto_analyzer import CryptoAnalyzer
        from src.sast_tools.crypto_detector import detect_crypto_patterns
        
        self.static_analyzer = CryptoAnalyzer()
        self.static_detector = detect_crypto_patterns
        
    def _load_crypto_patterns(self) -> Dict[str, List[str]]:
        """加载统一的加密模式配置"""
        # 优先使用JS逆向配置
        if self.js_reverse_config:
            patterns = self.js_reverse_config.get('crypto_patterns', {})
            return {
                'functions': patterns.get('function_patterns', []),
                'native_methods': patterns.get('native_methods', []),
                'libraries': [
                    'CryptoJS', 'JSEncrypt', 'sjcl', 'jsencrypt',
                    'aes', 'des', 'rsa', 'sha', 'md5'
                ]
            }
        
        # 默认模式
        return {
            'functions': [
                'encrypt', 'decrypt', 'cipher', 'digest', 'hash',
                'sign', 'verify', 'encode', 'decode'
            ],
            'native_methods': [
                'atob', 'btoa', 'eval', 'Function',
                'setTimeout', 'setInterval', 'crypto'
            ],
            'libraries': [
                'CryptoJS', 'JSEncrypt', 'sjcl', 'jsencrypt'
            ]
        }
    
    def _get_code_hash(self, code: str) -> str:
        """生成代码指纹用于缓存"""
        return hashlib.md5(code.encode('utf-8')).hexdigest()
    
    def _is_cache_valid(self, cache_entry: Dict) -> bool:
        """检查缓存是否有效"""
        return time.time() - cache_entry.get('timestamp', 0) < self.cache_ttl
    
    async def analyze_crypto(
        self, 
        code: str, 
        context: Dict[str, Any] = None,
        analysis_modes: List[str] = None
    ) -> List[CryptoFinding]:
        """
        统一的加密分析入口
        
        Args:
            code: 要分析的代码
            context: 分析上下文（URL、变量状态等）
            analysis_modes: 分析模式 ['static', 'dynamic', 'ai']
        
        Returns:
            统一的分析结果列表
        """
        if not code:
            return []
            
        # 检查缓存
        code_hash = self._get_code_hash(code)
        cache_key = f"{code_hash}:{str(analysis_modes or 'all')}"
        
        if cache_key in self.analysis_cache:
            cache_entry = self.analysis_cache[cache_key]
            if self._is_cache_valid(cache_entry):
                return cache_entry['findings']
        
        # 默认使用所有分析模式
        if analysis_modes is None:
            analysis_modes = ['static', 'dynamic', 'ai']
        
        findings = []
        
        # 1. 静态分析
        if 'static' in analysis_modes:
            static_findings = await self._static_analysis(code, context)
            findings.extend(static_findings)
        
        # 2. 动态分析（如果有运行时信息）
        if 'dynamic' in analysis_modes and context:
            dynamic_findings = await self._dynamic_analysis(code, context)
            findings.extend(dynamic_findings)
        
        # 3. AI增强分析
        if 'ai' in analysis_modes:
            ai_findings = await self._ai_analysis(code, context, findings)
            findings.extend(ai_findings)
        
        # 去重和合并
        findings = self._deduplicate_findings(findings)
        
        # 缓存结果
        self.analysis_cache[cache_key] = {
            'findings': findings,
            'timestamp': time.time()
        }
        
        return findings
    
    async def _static_analysis(self, code: str, context: Dict[str, Any]) -> List[CryptoFinding]:
        """静态加密分析"""
        findings = []
        
        # 使用原有的静态分析器
        try:
            # crypto_detector的结果
            static_results = self.static_detector(code)
            for result in static_results:
                findings.append(CryptoFinding(
                    type='pattern',
                    subtype=result.get('type', 'unknown'),
                    name=result.get('name', 'Unknown'),
                    description=result.get('description', ''),
                    severity=result.get('severity', 'Medium'),
                    confidence=0.8,  # 静态分析置信度较高
                    evidence=result.get('evidence', ''),
                    location={'file': context.get('url', 'unknown')},
                    recommendations=result.get('recommendations', []),
                    analysis_method='static'
                ))
        except Exception as e:
            pass  # 静态分析失败时继续
        
        # 使用crypto_analyzer增强
        try:
            # 这里可以调用crypto_analyzer的方法
            pass
        except Exception as e:
            pass
        
        return findings
    
    async def _dynamic_analysis(self, code: str, context: Dict[str, Any]) -> List[CryptoFinding]:
        """动态加密分析（基于运行时信息）"""
        findings = []
        
        # 分析运行时变量
        variables = context.get('variables', {})
        for var_name, var_value in variables.items():
            # 检查是否是密钥
            if self._is_likely_key(var_name, var_value):
                findings.append(CryptoFinding(
                    type='key',
                    subtype='runtime_variable',
                    name=var_name,
                    description=f"运行时检测到可能的密钥变量: {var_name}",
                    severity='High',
                    confidence=0.9,
                    evidence=f"Variable: {var_name} = {str(var_value)[:50]}...",
                    location={'url': context.get('url', ''), 'variable': var_name},
                    recommendations=["避免在客户端存储密钥", "使用服务端加密"],
                    analysis_method='dynamic'
                ))
        
        return findings
    
    async def _ai_analysis(self, code: str, context: Dict[str, Any], existing_findings: List[CryptoFinding]) -> List[CryptoFinding]:
        """AI增强的加密分析"""
        findings = []
        
        # 如果有LLM客户端，可以进行AI分析
        # 这里可以集成JS逆向的AI分析逻辑
        
        return findings
    
    def _is_likely_key(self, name: str, value: str) -> bool:
        """判断变量是否可能是密钥"""
        key_indicators = ['key', 'secret', 'token', 'password', 'salt', 'iv', 'nonce']
        name_lower = name.lower()
        
        # 检查变量名
        if any(indicator in name_lower for indicator in key_indicators):
            # 检查值特征
            if isinstance(value, str) and len(value) > 8:
                # 可能是密钥
                return True
        
        return False
    
    def _deduplicate_findings(self, findings: List[CryptoFinding]) -> List[CryptoFinding]:
        """去重和合并相似发现"""
        unique_findings = []
        seen = set()
        
        for finding in findings:
            # 创建唯一标识
            key = (finding.type, finding.subtype, finding.name)
            
            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)
        
        return unique_findings
    
    @lru_cache(maxsize=1000)
    def detect_crypto_functions(self, code: str) -> List[Dict[str, Any]]:
        """检测加密函数（带缓存）"""
        findings = []
        patterns = self.crypto_patterns['functions']
        
        # 构建正则表达式
        func_pattern = r'\b(' + '|'.join(patterns) + r')\w*\b'
        
        for match in re.finditer(func_pattern, code, re.IGNORECASE):
            findings.append({
                'name': match.group(),
                'type': 'function',
                'position': match.span(),
                'confidence': 0.7
            })
        
        return findings
    
    def get_analysis_summary(self, findings: List[CryptoFinding]) -> Dict[str, Any]:
        """生成分析摘要"""
        summary = {
            'total_findings': len(findings),
            'by_type': {},
            'by_severity': {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0},
            'by_method': {'static': 0, 'dynamic': 0, 'ai': 0}
        }
        
        for finding in findings:
            # 按类型统计
            ftype = finding.type
            summary['by_type'][ftype] = summary['by_type'].get(ftype, 0) + 1
            
            # 按严重度统计
            severity = finding.severity
            summary['by_severity'][severity] += 1
            
            # 按分析方法统计
            method = finding.analysis_method
            summary['by_method'][method] += 1
        
        return summary