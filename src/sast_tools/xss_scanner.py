

import re
from typing import List

LOCATION_HREF_JS_PATTERN = r"location\.href\s*=\s*['\"`]?javascript:"
DANGEROUS_SINKS = [
    r'\.innerHTML',
    r'\.outerHTML',
    r'document\.write\(',
    r'document\.writeln\(',
    r'eval\(',
    r'setTimeout\("[^\"]+"\)',
    r'setInterval\("[^\"]+"\)',
    LOCATION_HREF_JS_PATTERN,
]
SINK_PATTERN = re.compile("|".join(DANGEROUS_SINKS), re.IGNORECASE)

def find_xss_sinks(js_code: str) -> List[str]:
    """
    在给定的JavaScript代码中寻找潜在的XSS注入点（sinks）。
    """
    found_sinks = []
    matches = SINK_PATTERN.finditer(js_code)
    for match in matches:
        line_start = js_code.rfind('\n', 0, match.start()) + 1
        line_end = js_code.find('\n', match.end())
        if line_end == -1:
            line_end = len(js_code)
        line = js_code[line_start:line_end].strip()
        found_sinks.append(f"发现潜在的XSS注入点 '{match.group(0)}' 在代码行: `{line[:100]}`...")
    return found_sinks
