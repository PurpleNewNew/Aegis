"""
加密函数和API端点检测器
用于静态分析代码中的加密实现和API调用
"""
import re
from typing import List, Dict, Any

def detect_crypto_patterns(code: str) -> List[Dict[str, Any]]:
    """
    检测代码中的加密相关模式
    """
    findings = []
    
    # 加密库模式
    crypto_libraries = {
        'CryptoJS': r'CryptoJS\.(AES|DES|TripleDES|RC4|Rabbit)',
        'JSEncrypt': r'new\s+JSEncrypt\(\)',
        'Forge': r'forge\.(cipher|md|util)',
        'SJCL': r'sjcl\.(encrypt|decrypt|hash)',
        'bcrypt': r'bcrypt\.(hash|compare)',
        'MD5': r'(md5|MD5)\s*\(',
        'SHA': r'(sha256|sha512|SHA256|SHA512)\s*\(',
        'Base64': r'(btoa|atob|base64|Base64)',
    }
    
    for lib_name, pattern in crypto_libraries.items():
        matches = re.finditer(pattern, code, re.IGNORECASE)
        for match in matches:
            line_num = code[:match.start()].count('\n') + 1
            findings.append({
                'type': 'crypto_library',
                'library': lib_name,
                'line': line_num,
                'context': match.group(0),
                'severity': 'info'
            })
    
    # 加密密钥模式
    key_patterns = [
        (r'(aes|AES)[\s_-]?(key|KEY|Key)\s*[=:]\s*["\']([^"\']+)["\']', 'AES_KEY'),
        (r'(des|DES)[\s_-]?(key|KEY|Key)\s*[=:]\s*["\']([^"\']+)["\']', 'DES_KEY'),
        (r'(secret|SECRET|Secret)[\s_-]?(key|KEY|Key)\s*[=:]\s*["\']([^"\']+)["\']', 'SECRET_KEY'),
        (r'(encrypt|ENCRYPT)[\s_-]?(key|KEY|Key)\s*[=:]\s*["\']([^"\']+)["\']', 'ENCRYPT_KEY'),
        (r'(iv|IV|Iv)\s*[=:]\s*["\']([^"\']+)["\']', 'IV'),
        (r'(salt|SALT|Salt)\s*[=:]\s*["\']([^"\']+)["\']', 'SALT'),
    ]
    
    for pattern, key_type in key_patterns:
        matches = re.finditer(pattern, code)
        for match in matches:
            line_num = code[:match.start()].count('\n') + 1
            # 提取密钥值（如果存在）
            key_value = match.group(3) if len(match.groups()) >= 3 else match.group(2)
            findings.append({
                'type': 'crypto_key',
                'key_type': key_type,
                'line': line_num,
                'value': key_value[:20] + '...' if len(key_value) > 20 else key_value,
                'full_match': match.group(0),
                'severity': 'high'
            })
    
    # 加密函数调用模式
    encrypt_patterns = [
        (r'function\s+encrypt\s*\([^)]*\)', 'encrypt_function'),
        (r'function\s+decrypt\s*\([^)]*\)', 'decrypt_function'),
        (r'\.encrypt\s*\([^)]*\)', 'encrypt_call'),
        (r'\.decrypt\s*\([^)]*\)', 'decrypt_call'),
        (r'AES\.encrypt\s*\([^)]*\)', 'aes_encrypt'),
        (r'AES\.decrypt\s*\([^)]*\)', 'aes_decrypt'),
    ]
    
    for pattern, func_type in encrypt_patterns:
        matches = re.finditer(pattern, code, re.IGNORECASE)
        for match in matches:
            line_num = code[:match.start()].count('\n') + 1
            findings.append({
                'type': 'crypto_function',
                'function_type': func_type,
                'line': line_num,
                'context': match.group(0)[:100],
                'severity': 'medium'
            })
    
    return findings

def detect_api_endpoints(code: str) -> List[Dict[str, Any]]:
    """
    检测代码中的API端点
    """
    endpoints = []
    
    # API URL模式
    api_patterns = [
        # RESTful API
        r'["\']/(api|v1|v2|graphql)/[^"\']*["\']',
        # fetch/ajax调用
        r'fetch\s*\(["\']([^"\']+)["\']',
        r'\.ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']',
        r'axios\.(get|post|put|delete)\s*\(["\']([^"\']+)["\']',
        # XMLHttpRequest
        r'\.open\s*\(["\'](?:GET|POST|PUT|DELETE)["\'],\s*["\']([^"\']+)["\']',
    ]
    
    for pattern in api_patterns:
        matches = re.finditer(pattern, code, re.IGNORECASE)
        for match in matches:
            line_num = code[:match.start()].count('\n') + 1
            # 提取URL
            url = match.group(1) if match.lastindex else match.group(0)
            url = url.strip('"\'')
            
            # 判断是否是API端点
            if any(keyword in url for keyword in ['/api/', '/v1/', '/v2/', '/graphql', '.json']):
                endpoints.append({
                    'type': 'api_endpoint',
                    'url': url,
                    'line': line_num,
                    'context': match.group(0),
                    'severity': 'info'
                })
    
    # 检测可能的未授权API
    unauth_patterns = [
        (r'/api/users?/?', 'user_api'),
        (r'/api/admin/?', 'admin_api'),
        (r'/api/config/?', 'config_api'),
        (r'/api/list/?', 'list_api'),
        (r'/api/export/?', 'export_api'),
    ]
    
    for pattern, api_type in unauth_patterns:
        if re.search(pattern, code, re.IGNORECASE):
            endpoints.append({
                'type': 'potential_unauth_api',
                'api_type': api_type,
                'pattern': pattern,
                'severity': 'high'
            })
    
    return endpoints

def detect_authentication_patterns(code: str) -> List[Dict[str, Any]]:
    """
    检测认证相关的模式
    """
    findings = []
    
    # JWT模式
    jwt_patterns = [
        r'jwt\.(sign|verify|decode)',
        r'jsonwebtoken',
        r'Bearer\s+[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
    ]
    
    for pattern in jwt_patterns:
        matches = re.finditer(pattern, code, re.IGNORECASE)
        for match in matches:
            line_num = code[:match.start()].count('\n') + 1
            findings.append({
                'type': 'jwt_usage',
                'line': line_num,
                'context': match.group(0),
                'severity': 'info'
            })
    
    # 用户ID/UID模式
    uid_patterns = [
        r'(uid|UID|userId|user_id|UserID)\s*[=:]\s*(["\']?)(\d+|[a-zA-Z0-9\-]+)\2',
        r'["\']uid["\']\s*:\s*(["\']?)([^"\']+)\1',
    ]
    
    for pattern in uid_patterns:
        matches = re.finditer(pattern, code)
        for match in matches:
            line_num = code[:match.start()].count('\n') + 1
            findings.append({
                'type': 'user_identifier',
                'line': line_num,
                'context': match.group(0),
                'severity': 'medium'
            })
    
    return findings

def analyze_code(code: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    综合分析代码，返回所有发现
    """
    return {
        'crypto_patterns': detect_crypto_patterns(code),
        'api_endpoints': detect_api_endpoints(code),
        'auth_patterns': detect_authentication_patterns(code)
    }
