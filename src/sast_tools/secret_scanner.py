import re
from typing import List, Dict

# 正则表达式的灵感来源于 https://github.com/trufflesecurity/trufflehog
SECRET_PATTERNS = {
    'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
    'GitHub Token': r'ghp_[0-9a-zA-Z]{36}',
    'Slack Token': r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}',
    'Stripe API Key': r'sk_live_[0-9a-zA-Z]{24}',
    'AWS Access Key ID': r'AKIA[0-9A-Z]{16}',
    'Generic API Key': r'''[aA][pP][iI]_?[kK][eE][yY][\s"'=:]+([\w\-]{20,})\b''',
}

def find_secrets(text_content: str) -> List[Dict[str, str]]:
    """
    在给定的文本内容中寻找硬编码的密钥。
    """
    found_secrets = []
    for key_type, pattern in SECRET_PATTERNS.items():
        try:
            matches = re.findall(pattern, text_content)
            for match in matches:
                actual_match = match if isinstance(match, str) else match[0]
                if actual_match:
                    found_secrets.append({
                        'type': key_type,
                        'value': f"...{actual_match[-4:]}" # 脱敏处理
                    })
        except re.error as e:
            print(f"正则表达式错误: {e} for pattern: {pattern}")
    return found_secrets