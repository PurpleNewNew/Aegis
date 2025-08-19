
import asyncio
import json
from playwright.async_api import Page, Request, Response
from typing import List, Dict, Any, Optional

async def navigate(page: Page, url: str) -> str:
    """导航到指定的URL。"""
    try:
        await page.goto(url, wait_until='domcontentloaded', timeout=15000)
        return f"成功导航到: {url}"
    except Exception as e:
        return f"导航失败: {e}"

async def get_web_content(page: Page) -> str:
    """获取当前页面的简化版HTML内容。"""
    try:
        await page.evaluate("() => { document.querySelectorAll('script, style').forEach(el => el.remove()); }")
        content = await page.content()
        return content[:8000] + "... (内容过长已被截断)"
    except Exception as e:
        return f"获取页面内容失败: {e}"

async def get_interactive_elements(page: Page) -> List[Dict[str, str]]:
    """获取页面上所有可交互的元素。"""
    try:
        js_code = """() => {
            const selectors = [];
            const query = 'a, button, input:not([type=hidden]), textarea, select, [role=button], [onclick]';
            document.querySelectorAll(query).forEach((el, i) => {
                const rect = el.getBoundingClientRect();
                if (rect.width === 0 || rect.height === 0) return;
                let text = el.innerText || el.value || el.getAttribute('aria-label') || el.getAttribute('placeholder') || '';
                text = text.trim().substring(0, 50);
                const unique_id = `aegis-el-${i}`;
                el.setAttribute('data-aegis-id', unique_id);
                selectors.push({
                    selector: `[data-aegis-id="${unique_id}"]`,
                    role: el.tagName.toLowerCase(),
                    text: text,
                    aegis_id: unique_id
                });
            });
            return selectors;
        }"""
        elements = await page.evaluate(js_code)
        return elements
    except Exception as e:
        return [{"error": f"获取可交互元素失败: {e}"}]

async def get_forms(page: Page) -> List[Dict[str, Any]]:
    """获取页面上的所有表单及其字段信息。"""
    try:
        js_code = """() => {
            const forms = [];
            document.querySelectorAll('form').forEach((form, formIndex) => {
                const formData = {
                    id: form.id || `form_${formIndex}`,
                    action: form.action || '',
                    method: form.method || 'GET',
                    fields: []
                };
                
                // 获取表单内的输入字段
                form.querySelectorAll('input, textarea, select').forEach((field, fieldIndex) => {
                    if (field.type === 'hidden' && !field.name.toLowerCase().includes('token')) {
                        return; // 跳过隐藏字段（除非是token相关）
                    }
                    
                    const unique_id = `aegis-form-${formIndex}-field-${fieldIndex}`;
                    field.setAttribute('data-aegis-id', unique_id);
                    
                    formData.fields.push({
                        selector: `[data-aegis-id="${unique_id}"]`,
                        type: field.type || field.tagName.toLowerCase(),
                        name: field.name || '',
                        id: field.id || '',
                        placeholder: field.placeholder || '',
                        required: field.required || false,
                        value: field.value || '',
                        aegis_id: unique_id
                    });
                });
                
                // 查找提交按钮
                const submitBtn = form.querySelector('button[type="submit"], input[type="submit"], button:not([type])');
                if (submitBtn) {
                    const btnId = `aegis-form-${formIndex}-submit`;
                    submitBtn.setAttribute('data-aegis-id', btnId);
                    formData.submit_button = {
                        selector: `[data-aegis-id="${btnId}"]`,
                        text: submitBtn.innerText || submitBtn.value || 'Submit',
                        aegis_id: btnId
                    };
                }
                
                forms.push(formData);
            });
            return forms;
        }"""
        forms = await page.evaluate(js_code)
        return forms
    except Exception as e:
        return [{"error": f"获取表单信息失败: {e}"}]

async def click_element(page: Page, selector: str) -> str:
    """点击一个由选择器指定的元素。"""
    try:
        await page.click(selector, timeout=5000)
        await asyncio.sleep(3) # 等待页面响应或发生跳转
        return f"成功点击元素: {selector}。当前URL: {page.url}"
    except Exception as e:
        return f"点击元素失败: {selector}, 错误: {e}"

async def input_text(page: Page, selector: str, text: str) -> str:
    """在一个由选择器指定的输入框中输入文本。"""
    try:
        await page.fill(selector, text, timeout=5000)
        return f"成功向元素 {selector} 输入文本。"
    except Exception as e:
        return f"向元素 {selector} 输入文本失败: {e}"

async def execute_javascript(page: Page, code: str) -> str:
    """在页面中执行JavaScript代码并返回结果。用于动态分析和提取信息。"""
    try:
        # 包装代码以确保返回值
        wrapped_code = f"(async () => {{ {code} }})()"
        result = await page.evaluate(wrapped_code)
        
        # 处理不同类型的返回值
        if result is None:
            return "执行成功，无返回值"
        elif isinstance(result, (dict, list)):
            return json.dumps(result, ensure_ascii=False, indent=2)
        else:
            return str(result)
    except Exception as e:
        return f"JavaScript执行失败: {e}"

async def get_javascript_variables(page: Page, pattern: str = ".*") -> str:
    """提取页面中的JavaScript全局变量，支持正则匹配。用于发现加密密钥、配置等。"""
    try:
        code = f"""
        () => {{
            const vars = {{}};
            const pattern = new RegExp('{pattern}', 'i');
            
            // 遍历window对象
            for (let key in window) {{
                if (pattern.test(key)) {{
                    try {{
                        const value = window[key];
                        const type = typeof value;
                        
                        // 跳过函数和DOM元素
                        if (type === 'function' || value instanceof Element) {{
                            continue;
                        }}
                        
                        // 处理不同类型的值
                        if (type === 'object' && value !== null) {{
                            // 尝试JSON序列化
                            try {{
                                vars[key] = JSON.parse(JSON.stringify(value));
                            }} catch {{
                                vars[key] = String(value);
                            }}
                        }} else {{
                            vars[key] = value;
                        }}
                    }} catch(e) {{
                        // 忽略无法访问的属性
                    }}
                }}
            }}
            return vars;
        }}
        """
        
        result = await page.evaluate(code)
        return json.dumps(result, ensure_ascii=False, indent=2)
    except Exception as e:
        return f"获取JavaScript变量失败: {e}"

async def get_crypto_functions(page: Page) -> str:
    """检测页面中的加密相关函数和变量，用于发现加密密钥。"""
    try:
        code = """
        () => {
            const cryptoInfo = {
                crypto_libraries: [],
                potential_keys: {},
                crypto_functions: []
            };
            
            // 检测常见的加密库
            const cryptoLibs = ['CryptoJS', 'jsencrypt', 'forge', 'sjcl', 'bcrypt', 'md5', 'sha256', 'AES', 'RSA', 'DES'];
            cryptoLibs.forEach(lib => {
                if (typeof window[lib] !== 'undefined') {
                    cryptoInfo.crypto_libraries.push(lib);
                }
            });
            
            // 搜索可能的密钥变量
            const keyPatterns = ['key', 'secret', 'password', 'token', 'salt', 'iv', 'aes', 'des', 'rsa'];
            for (let key in window) {
                const lowerKey = key.toLowerCase();
                if (keyPatterns.some(pattern => lowerKey.includes(pattern))) {
                    const value = window[key];
                    if (typeof value === 'string' && value.length > 5) {
                        cryptoInfo.potential_keys[key] = value.substring(0, 50) + (value.length > 50 ? '...' : '');
                    }
                }
            }
            
            // 检测加密相关的函数
            for (let key in window) {
                const value = window[key];
                if (typeof value === 'function') {
                    const funcStr = value.toString();
                    if (funcStr.match(/encrypt|decrypt|hash|sign|verify|encode|decode/i)) {
                        cryptoInfo.crypto_functions.push({
                            name: key,
                            preview: funcStr.substring(0, 100) + '...'
                        });
                    }
                }
            }
            
            return cryptoInfo;
        }
        """
        
        result = await page.evaluate(code)
        return json.dumps(result, ensure_ascii=False, indent=2)
    except Exception as e:
        return f"检测加密函数失败: {e}"

async def intercept_network_requests(page: Page, duration_ms: int = 5000) -> str:
    """拦截并记录网络请求，用于发现API端点和数据传输。"""
    try:
        requests_data = []
        
        def handle_request(request: Request):
            """处理拦截到的请求"""
            req_data = {
                'url': request.url,
                'method': request.method,
                'headers': dict(request.headers),
                'post_data': request.post_data
            }
            
            # 识别API端点
            if any(keyword in request.url for keyword in ['/api/', '/v1/', '/v2/', '.json', '/graphql']):
                req_data['type'] = 'API'
            elif request.url.endswith(('.js', '.css', '.png', '.jpg', '.gif')):
                req_data['type'] = 'Resource'
            else:
                req_data['type'] = 'Page'
                
            requests_data.append(req_data)
        
        def handle_response(response: Response):
            """处理响应，记录状态码"""
            for req in requests_data:
                if req['url'] == response.url:
                    req['status'] = response.status
                    break
        
        # 注册事件监听器
        page.on('request', handle_request)
        page.on('response', handle_response)
        
        # 等待指定时间收集请求
        await asyncio.sleep(duration_ms / 1000)
        
        # 移除监听器
        page.remove_listener('request', handle_request)
        page.remove_listener('response', handle_response)
        
        # 过滤和分析请求
        api_requests = [r for r in requests_data if r.get('type') == 'API']
        
        result = {
            'total_requests': len(requests_data),
            'api_endpoints': api_requests,
            'interesting_requests': [r for r in requests_data if r.get('post_data')]
        }
        
        return json.dumps(result, ensure_ascii=False, indent=2)
    except Exception as e:
        return f"拦截网络请求失败: {e}"

async def get_form_data(page: Page) -> str:
    """获取页面上所有表单的详细信息，包括action、method和输入字段。"""
    try:
        code = """
        () => {
            const forms = [];
            document.querySelectorAll('form').forEach((form, index) => {
                const formData = {
                    index: index,
                    action: form.action || 'current_page',
                    method: form.method || 'GET',
                    inputs: []
                };
                
                form.querySelectorAll('input, textarea, select').forEach(input => {
                    formData.inputs.push({
                        name: input.name || input.id,
                        type: input.type || input.tagName.toLowerCase(),
                        value: input.value,
                        required: input.required,
                        pattern: input.pattern,
                        placeholder: input.placeholder
                    });
                });
                
                forms.push(formData);
            });
            return forms;
        }
        """
        
        result = await page.evaluate(code)
        return json.dumps(result, ensure_ascii=False, indent=2)
    except Exception as e:
        return f"获取表单数据失败: {e}"

async def check_console_errors(page: Page) -> str:
    """检查浏览器控制台的错误和警告信息。"""
    try:
        # 收集控制台消息
        console_messages = []
        
        def handle_console(msg):
            console_messages.append({
                'type': msg.type,
                'text': msg.text,
                'location': msg.location
            })
        
        page.on('console', handle_console)
        
        # 触发可能的错误
        await page.evaluate("console.log('Aegis Console Check');")
        
        # 等待一下收集更多消息
        await asyncio.sleep(1)
        
        page.remove_listener('console', handle_console)
        
        # 过滤错误和警告
        errors = [m for m in console_messages if m['type'] in ['error', 'warning']]
        
        return json.dumps({
            'total_messages': len(console_messages),
            'errors_warnings': errors
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return f"检查控制台错误失败: {e}"

# 定义所有可用的工具
AVAILABLE_TOOLS = [
    'navigate', 'get_web_content', 'get_interactive_elements', 
    'click_element', 'input_text', 'execute_javascript',
    'get_javascript_variables', 'get_crypto_functions',
    'intercept_network_requests', 'get_form_data', 'check_console_errors'
]
