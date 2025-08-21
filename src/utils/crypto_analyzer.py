import re
import logging
from typing import Dict, List, Any, Optional

class CryptoAnalyzer:
    """
    加密场景识别和分析工具
    用于识别JavaScript代码中的不同加密模式和安全机制
    """
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # 定义各种加密算法的识别模式
        self.encryption_patterns = {
            'AES': [
                r'\bAES\b',
                r'\baes\b',
                r'\.encrypt\(',
                r'\.decrypt\(',
                r'CryptoJS\.AES',
                r'crypto\.createCipher',
                r'crypto\.createDecipher'
            ],
            'RSA': [
                r'\bRSA\b',
                r'\brsa\b',
                r'JSEncrypt',
                r'\.setPublicKey\(',
                r'\.setPrivateKey\(',
                r'\.encrypt\(',
                r'\.decrypt\('
            ],
            'DES': [
                r'\bDES\b',
                r'\bdes\b',
                r'TripleDES',
                r'CryptoJS\.DES',
                r'CryptoJS\.TripleDES'
            ],
            'SM2': [
                r'\bSM2\b',
                r'\bsm2\b'
            ],
            'SM4': [
                r'\bSM4\b',
                r'\bsm4\b'
            ]
        }
        
        # 定义签名算法的识别模式
        self.signature_patterns = {
            'HMAC': [
                r'\bHMAC\b',
                r'\bhmac\b',
                r'CryptoJS\.Hmac',
                r'crypto\.createHmac'
            ],
            'MD5': [
                r'\bMD5\b',
                r'\bmd5\b',
                r'CryptoJS\.MD5'
            ],
            'SHA': [
                r'\bSHA\d*\b',
                r'\bsha\d*\b',
                r'CryptoJS\.SHA'
            ]
        }
        
        # 定义密钥管理方式的识别模式
        self.key_management_patterns = {
            'fixed': [
                r'["\'][A-Fa-f0-9]{16,}["\']',  # 16进制字符串
                r'["\'][A-Za-z0-9+/]{16,}["\']'  # Base64字符串
            ],
            'server_fetched': [
                r'\.fetch\([''"]*/api/.*key',
                r'\.ajax\([''"]*/api/.*key',
                r'\.get\([''"]*/api/.*key'
            ]
        }
        
        # 定义安全机制的识别模式
        self.security_mechanism_patterns = {
            'anti_replay': [
                r'\bnonce\b',
                r'\btimestamp\b',
                r'\btime\b.*\bnow\b'
            ],
            'timestamp': [
                r'Date\.now\(\)',
                r'new Date\(\)',
                r'\bgetTime\(\)'
            ]
        }

    def analyze_code_snippet(self, code_snippet: str) -> Dict[str, Any]:
        """
        分析代码片段，识别其中的加密算法、签名算法、密钥管理方式和安全机制
        
        Args:
            code_snippet: JavaScript代码片段
            
        Returns:
            包含识别结果的字典
        """
        result = {
            'algorithms': [],
            'signatures': [],
            'key_management': 'unknown',
            'security_mechanisms': [],
            'vulnerabilities': []
        }
        
        # 识别加密算法
        result['algorithms'] = self._identify_algorithms(code_snippet, self.encryption_patterns)
        
        # 识别签名算法
        result['signatures'] = self._identify_algorithms(code_snippet, self.signature_patterns)
        
        # 识别密钥管理方式
        result['key_management'] = self._identify_key_management(code_snippet)
        
        # 识别安全机制
        result['security_mechanisms'] = self._identify_security_mechanisms(code_snippet)
        
        # 识别潜在漏洞
        result['vulnerabilities'] = self._identify_vulnerabilities(code_snippet, result)
        
        return result

    def _identify_algorithms(self, code_snippet: str, patterns: Dict[str, List[str]]) -> List[str]:
        """识别代码中的算法"""
        found_algorithms = []
        for algorithm, pattern_list in patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, code_snippet, re.IGNORECASE):
                    if algorithm not in found_algorithms:
                        found_algorithms.append(algorithm)
        return found_algorithms

    def _identify_key_management(self, code_snippet: str) -> str:
        """识别密钥管理方式"""
        for key_type, pattern_list in self.key_management_patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, code_snippet, re.IGNORECASE):
                    return key_type
        return 'unknown'

    def _identify_security_mechanisms(self, code_snippet: str) -> List[str]:
        """识别安全机制"""
        found_mechanisms = []
        for mechanism, pattern_list in self.security_mechanism_patterns.items():
            for pattern in pattern_list:
                if re.search(pattern, code_snippet, re.IGNORECASE):
                    if mechanism not in found_mechanisms:
                        found_mechanisms.append(mechanism)
        return found_mechanisms

    def _identify_vulnerabilities(self, code_snippet: str, analysis_result: Dict[str, Any]) -> List[str]:
        """识别潜在漏洞"""
        vulnerabilities = []
        
        # 检查固定密钥漏洞
        if analysis_result['key_management'] == 'fixed':
            vulnerabilities.append('fixed_key')
            
        # 检查弱加密算法
        weak_algorithms = ['DES']
        for alg in weak_algorithms:
            if alg in analysis_result['algorithms']:
                vulnerabilities.append('weak_algorithm')
                
        # 检查缺少安全机制
        if not analysis_result['security_mechanisms']:
            vulnerabilities.append('no_anti_replay')
            
        return vulnerabilities

    def enhance_analysis_with_static_patterns(self, ai_analysis: Dict[str, Any], code_snippet: str) -> Dict[str, Any]:
        """
        结合静态模式分析增强AI分析结果
        
        Args:
            ai_analysis: AI分析结果
            code_snippet: JavaScript代码片段
            
        Returns:
            增强后的分析结果
        """
        static_analysis = self.analyze_code_snippet(code_snippet)
        
        # 合并算法识别结果
        if 'algorithms' in ai_analysis:
            combined_algorithms = list(set(ai_analysis['algorithms'] + static_analysis['algorithms']))
            ai_analysis['algorithms'] = combined_algorithms
        else:
            ai_analysis['algorithms'] = static_analysis['algorithms']
            
        # 合并签名算法识别结果
        if 'signatures' not in ai_analysis and static_analysis['signatures']:
            ai_analysis['signatures'] = static_analysis['signatures']
            
        # 如果AI未识别密钥管理方式，使用静态分析结果
        if ai_analysis.get('key_management') in [None, 'unknown'] and static_analysis['key_management'] != 'unknown':
            ai_analysis['key_management'] = static_analysis['key_management']
            
        # 合并安全机制
        if 'security_mechanisms' in ai_analysis:
            combined_mechanisms = list(set(ai_analysis['security_mechanisms'] + static_analysis['security_mechanisms']))
            ai_analysis['security_mechanisms'] = combined_mechanisms
        elif static_analysis['security_mechanisms']:
            ai_analysis['security_mechanisms'] = static_analysis['security_mechanisms']
            
        # 合并漏洞识别
        if 'vulnerabilities' in ai_analysis:
            combined_vulnerabilities = list(set(ai_analysis['vulnerabilities'] + static_analysis['vulnerabilities']))
            ai_analysis['vulnerabilities'] = combined_vulnerabilities
        elif static_analysis['vulnerabilities']:
            ai_analysis['vulnerabilities'] = static_analysis['vulnerabilities']
            
        return ai_analysis