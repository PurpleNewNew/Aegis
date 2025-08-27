import re
import json
from typing import Dict, Any, List, Optional
import logging

logger = logging.getLogger(__name__)

class CryptoAnalyzer:
    """
    加密分析工具，用于静态分析JavaScript代码中的加密模式
    """
    
    def __init__(self):
        # 加密算法模式
        self.crypto_patterns = {
            'AES': {
                'regex': r'\b(?:AES|aes|Aes)\s*(?:-\d{3})?\b',
                'key_sizes': [128, 192, 256],
                'modes': ['CBC', 'ECB', 'CTR', 'GCM', 'CFB', 'OFB']
            },
            'DES': {
                'regex': r'\b(?:DES|des|Des)\b',
                'key_sizes': [56],
                'modes': ['CBC', 'ECB']
            },
            '3DES': {
                'regex': r'\b(?:3DES|TripleDES|tripleDES|3des)\b',
                'key_sizes': [168],
                'modes': ['CBC', 'ECB']
            },
            'RSA': {
                'regex': r'\b(?:RSA|rsa|Rsa)\b',
                'key_sizes': [1024, 2048, 3072, 4096]
            },
            'MD5': {
                'regex': r'\b(?:MD5|md5)\b',
                'output_size': 128
            },
            'SHA': {
                'regex': r'\b(?:SHA|sha)\s*-?\s*\d{1,3}\b',
                'variants': ['SHA-1', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512', 'SHA-3']
            },
            'HMAC': {
                'regex': r'\b(?:HMAC|hmac)\b',
                'algorithms': ['MD5', 'SHA-1', 'SHA-256', 'SHA-512']
            },
            'Base64': {
                'regex': r'\b(?:atob|btoa|base64|Base64)\b'
            },
            'URIEncode': {
                'regex': r'\b(?:encodeURIComponent|decodeURIComponent)\b'
            }
        }
        
        # 密钥相关模式
        self.key_patterns = [
            r'\b(?:key|Key|KEY|secret|Secret|SECRET|password|Password|PASSWORD)\s*[:=]\s*["\']([^"\']+)["\']',
            r'\b(?:key|Key|KEY|secret|Secret|SECRET)\s*=\s*([a-zA-Z0-9+/=]{20,})',
            r'\b(?:privateKey|publicKey|private_key|public_key)\s*[:=]\s*["\']([^"\']+)["\']'
        ]
        
        # IV/Nonce模式
        self.iv_patterns = [
            r'\b(?:iv|IV|nonce|Nonce)\s*[:=]\s*["\']([^"\']+)["\']',
            r'\b(?:iv|IV|nonce|Nonce)\s*=\s*([a-zA-Z0-9+/=]{16,})'
        ]
        
        # 加密函数调用模式
        self.encrypt_function_patterns = [
            r'\.encrypt\s*\(',
            r'\.decrypt\s*\(',
            r'\.sign\s*\(',
            r'\.verify\s*\(',
            r'\.hash\s*\(',
            r'\.digest\s*\(',
            r'\.update\s*\(',
            r'\.finalize\s*\(',
            r'CryptoJS\.AES\.encrypt',
            r'CryptoJS\.AES\.decrypt',
            r'CryptoJS\.DES\.encrypt',
            r'CryptoJS\.DES\.decrypt',
            r'CryptoJS\.RSA\.encrypt',
            r'CryptoJS\.RSA\.decrypt',
            r'JSEncrypt\.encrypt',
            r'JSEncrypt\.decrypt'
        ]
        
        # 安全弱点模式
        self.vulnerability_patterns = {
            'hardcoded_key': r'\b(?:key|Key|KEY)\s*[:=]\s*["\']([a-zA-Z0-9]{8,})["\']',
            'fixed_iv': r'\b(?:iv|IV)\s*[:=]\s*["\']([a-zA-Z0-9]{16,})["\']',
            'ecb_mode': r'\b(?:AES|DES|3DES).*?ECB\b',
            'md5_usage': r'\bMD5\b',
            'sha1_usage': r'\bSHA-?1\b',
            'no_iv': r'\b(?:AES|DES|3DES).*?(?!iv|IV)',
            'predictable_nonce': r'\b(?:nonce|Nonce)\s*[:=]\s*["\']?\d+["\']?'
        }

    def detect_crypto_patterns(self, code: str) -> Dict[str, Any]:
        """检测代码中的加密模式"""
        results = {
            'algorithms': [],
            'potential_keys': [],
            'potential_ivs': [],
            'function_calls': [],
            'vulnerabilities': []
        }
        
        # 检测加密算法
        for algo_name, pattern_info in self.crypto_patterns.items():
            matches = re.finditer(pattern_info['regex'], code, re.IGNORECASE)
            for match in matches:
                results['algorithms'].append({
                    'algorithm': algo_name,
                    'match': match.group(),
                    'line': self._get_line_number(code, match.start())
                })
        
        # 检测密钥
        for pattern in self.key_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                key_value = match.group(1)
                if key_value and len(key_value) >= 8:  # 过滤太短的值
                    results['potential_keys'].append({
                        'value': key_value[:50] + '...' if len(key_value) > 50 else key_value,
                        'type': 'literal' if re.match(r'^[a-zA-Z0-9+/=]+$', key_value) else 'variable',
                        'line': self._get_line_number(code, match.start())
                    })
        
        # 检测IV/Nonce
        for pattern in self.iv_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                iv_value = match.group(1)
                if iv_value:
                    results['potential_ivs'].append({
                        'value': iv_value[:50] + '...' if len(iv_value) > 50 else iv_value,
                        'line': self._get_line_number(code, match.start())
                    })
        
        # 检测加密函数调用
        for pattern in self.encrypt_function_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                results['function_calls'].append({
                    'function': match.group(),
                    'line': self._get_line_number(code, match.start())
                })
        
        # 检测安全弱点
        for vuln_type, pattern in self.vulnerability_patterns.items():
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                results['vulnerabilities'].append({
                    'type': vuln_type,
                    'description': self._get_vulnerability_description(vuln_type, match),
                    'line': self._get_line_number(code, match.start())
                })
        
        return results

    def enhance_analysis_with_static_patterns(self, ai_result: Dict[str, Any], code_snippet: str) -> Dict[str, Any]:
        """使用静态分析增强AI分析结果"""
        # 执行静态分析
        static_results = self.detect_crypto_patterns(code_snippet)
        
        # 合并算法检测结果
        if static_results['algorithms']:
            existing_algorithms = ai_result.get('algorithms', [])
            static_algorithms = [algo['algorithm'] for algo in static_results['algorithms']]
            combined_algorithms = list(set(existing_algorithms + static_algorithms))
            ai_result['algorithms'] = combined_algorithms
        
        # 增强密钥来源信息
        if static_results['potential_keys'] and ai_result.get('key_source') == 'unknown':
            # 如果静态分析发现了硬编码密钥
            hardcoded_keys = [k for k in static_results['potential_keys'] if k['type'] == 'literal']
            if hardcoded_keys:
                ai_result['key_source'] = "代码中硬编码的固定密钥"
                ai_result['key_management'] = 'fixed'
        
        # 增强安全弱点检测
        if static_results['vulnerabilities']:
            existing_vulns = ai_result.get('vulnerabilities', [])
            static_vulns = [v['type'] for v in static_results['vulnerabilities']]
            combined_vulns = list(set(existing_vulns + static_vulns))
            ai_result['vulnerabilities'] = combined_vulns
        
        # 添加静态分析发现的附加信息
        ai_result['static_analysis_findings'] = {
            'detected_algorithms': [algo['algorithm'] for algo in static_results['algorithms']],
            'key_findings': len(static_results['potential_keys']),
            'iv_findings': len(static_results['potential_ivs']),
            'function_calls': len(static_results['function_calls']),
            'vulnerability_count': len(static_results['vulnerabilities'])
        }
        
        return ai_result

    def _get_line_number(self, code: str, position: int) -> int:
        """获取代码行号"""
        return code[:position].count('\n') + 1

    def _get_vulnerability_description(self, vuln_type: str, match) -> str:
        """获取安全弱点描述"""
        descriptions = {
            'hardcoded_key': f"硬编码密钥: {match.group(1)[:20]}...",
            'fixed_iv': f"固定的初始化向量(IV): {match.group(1)[:20]}...",
            'ecb_mode': "使用ECB模式加密，可能导致模式泄露",
            'md5_usage': "使用MD5哈希算法，存在碰撞风险",
            'sha1_usage': "使用SHA-1哈希算法，存在碰撞风险",
            'no_iv': "未使用初始化向量(IV)，可能降低安全性",
            'predictable_nonce': "使用可预测的Nonce值"
        }
        return descriptions.get(vuln_type, "未知安全弱点")

    def analyze_crypto_usage(self, code: str) -> Dict[str, Any]:
        """分析代码中加密使用情况的完整报告"""
        patterns = self.detect_crypto_patterns(code)
        
        # 生成报告
        report = {
            'summary': {
                'total_algorithms': len(patterns['algorithms']),
                'total_keys': len(patterns['potential_keys']),
                'total_ivs': len(patterns['potential_ivs']),
                'total_vulnerabilities': len(patterns['vulnerabilities'])
            },
            'findings': patterns,
            'recommendations': self._generate_recommendations(patterns)
        }
        
        return report

    def _generate_recommendations(self, patterns: Dict[str, Any]) -> List[str]:
        """根据分析结果生成建议"""
        recommendations = []
        
        # 算法相关建议
        algorithms = [algo['algorithm'] for algo in patterns['algorithms']]
        if 'MD5' in algorithms:
            recommendations.append("建议将MD5替换为更安全的哈希算法，如SHA-256")
        if 'SHA-1' in algorithms:
            recommendations.append("建议将SHA-1替换为更安全的哈希算法，如SHA-256")
        if 'DES' in algorithms:
            recommendations.append("建议将DES替换为更强大的加密算法，如AES-256")
        
        # 密钥管理建议
        if patterns['potential_keys']:
            hardcoded_keys = [k for k in patterns['potential_keys'] if k['type'] == 'literal']
            if hardcoded_keys:
                recommendations.append("避免在代码中硬编码密钥，建议使用安全的密钥管理方案")
        
        # 安全弱点建议
        vuln_types = [v['type'] for v in patterns['vulnerabilities']]
        if 'hardcoded_key' in vuln_types:
            recommendations.append("检测到硬编码密钥，建议从安全配置或服务端动态获取")
        if 'fixed_iv' in vuln_types:
            recommendations.append("检测到固定的IV，建议为每次加密生成唯一的IV")
        if 'ecb_mode' in vuln_types:
            recommendations.append("检测到ECB模式，建议使用CBC或GCM模式")
        if 'no_iv' in vuln_types:
            recommendations.append("建议为分组加密使用适当的IV")
        
        return recommendations