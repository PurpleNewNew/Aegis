
from typing import List
from urllib.parse import urlparse

# 一个非常基础的技术栈/框架指纹识别启发式规则
# 真实世界的工具会更复杂，可能会检查JS变量、HTML内容等
FINGERPRINT_RULES = {
    'Java': ['.jsp', '.do', '.action'],
    'ASP.NET': ['.aspx', '.asmx'],
    'PHP': ['.php'],
    'WordPress': ['/wp-content/', '/wp-login/'],
    'React': ['react.js', 'react-dom.js'],
    'Vue.js': ['vue.js']
}

def get_preliminary_fingerprint(url: str) -> List[str]:
    """
    根据URL，快速、启发式地猜测网站的技术栈指纹。
    """
    fingerprints = set()
    path = urlparse(url).path.lower()
    
    for tech, indicators in FINGERPRINT_RULES.items():
        for indicator in indicators:
            if indicator in path:
                fingerprints.add(tech)
                break
    
    return list(fingerprints)