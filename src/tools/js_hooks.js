
// Aegis IAST Hook Script
// 这个脚本将在目标页面的任何其他脚本之前运行，以确保我们能成功地“劫持”原生函数。

console.log("Aegis IAST Hook正在注入...");

// 定义我们要监控的危险属性和函数
const sinks = {
    // DOM XSS Sinks
    'Element.prototype.innerHTML': {
        type: 'property',
        obj: Element.prototype,
        prop: 'innerHTML',
        risk: 'DOM XSS'
    },
    'Element.prototype.outerHTML': {
        type: 'property',
        obj: Element.prototype,
        prop: 'outerHTML',
        risk: 'DOM XSS'
    },
    'document.write': {
        type: 'function',
        obj: document,
        prop: 'write',
        risk: 'DOM XSS'
    },
    'document.writeln': {
        type: 'function',
        obj: document,
        prop: 'writeln',
        risk: 'DOM XSS'
    },
    
    // JavaScript Execution Sinks
    'eval': {
        type: 'function',
        obj: window,
        prop: 'eval',
        risk: 'Code Injection'
    },
    'Function': {
        type: 'constructor',
        obj: window,
        prop: 'Function',
        risk: 'Code Injection'
    },
    'setTimeout': {
        type: 'function',
        obj: window,
        prop: 'setTimeout',
        risk: 'Code Injection',
        checkString: true  // 只在参数是字符串时报告
    },
    'setInterval': {
        type: 'function',
        obj: window,
        prop: 'setInterval',
        risk: 'Code Injection',
        checkString: true
    },
    'setImmediate': {
        type: 'function',
        obj: window,
        prop: 'setImmediate',
        risk: 'Code Injection',
        checkString: true,
        optional: true  // 不是所有浏览器都支持
    },
    
    // URL Manipulation Sinks
    'location.href': {
        type: 'property',
        obj: location,
        prop: 'href',
        risk: 'Open Redirect / JavaScript URL'
    },
    'location.assign': {
        type: 'function',
        obj: location,
        prop: 'assign',
        risk: 'Open Redirect / JavaScript URL'
    },
    'location.replace': {
        type: 'function',
        obj: location,
        prop: 'replace',
        risk: 'Open Redirect / JavaScript URL'
    },
    'window.open': {
        type: 'function',
        obj: window,
        prop: 'open',
        risk: 'Open Redirect / Popup'
    },
    
    // jQuery Sinks (动态检测)
    'jQuery.html': {
        type: 'function',
        obj: null, // 将在后面动态设置
        prop: 'html',
        risk: 'jQuery DOM XSS',
        optional: true,
        jquery: true
    },
    'jQuery.append': {
        type: 'function',
        obj: null,
        prop: 'append',
        risk: 'jQuery DOM XSS',
        optional: true,
        jquery: true
    },
    'jQuery.prepend': {
        type: 'function',
        obj: null,
        prop: 'prepend',
        risk: 'jQuery DOM XSS',
        optional: true,
        jquery: true
    },
    'jQuery.after': {
        type: 'function',
        obj: null,
        prop: 'after',
        risk: 'jQuery DOM XSS',
        optional: true,
        jquery: true
    },
    'jQuery.before': {
        type: 'function',
        obj: null,
        prop: 'before',
        risk: 'jQuery DOM XSS',
        optional: true,
        jquery: true
    },
    'jQuery.replaceWith': {
        type: 'function',
        obj: null,
        prop: 'replaceWith',
        risk: 'jQuery DOM XSS',
        optional: true,
        jquery: true
    },
    
    // Local Storage Sinks
    'localStorage.setItem': {
        type: 'function',
        obj: localStorage,
        prop: 'setItem',
        risk: 'Sensitive Data Storage'
    },
    'sessionStorage.setItem': {
        type: 'function',
        obj: sessionStorage,
        prop: 'setItem',
        risk: 'Sensitive Data Storage'
    },
    
    // Cookie Manipulation
    'document.cookie': {
        type: 'property',
        obj: document,
        prop: 'cookie',
        risk: 'Cookie Manipulation'
    },
    
    // PostMessage
    'window.postMessage': {
        type: 'function',
        obj: window,
        prop: 'postMessage',
        risk: 'Cross-Origin Communication'
    },
    
    // Script/Link Element Creation
    'HTMLScriptElement.prototype.src': {
        type: 'property',
        obj: typeof HTMLScriptElement !== 'undefined' ? HTMLScriptElement.prototype : null,
        prop: 'src',
        risk: 'Script Injection',
        optional: true
    },
    'HTMLLinkElement.prototype.href': {
        type: 'property',
        obj: typeof HTMLLinkElement !== 'undefined' ? HTMLLinkElement.prototype : null,
        prop: 'href',
        risk: 'Style Injection',
        optional: true
    }
};

// 暴露给Python的回调函数，函数名必须与AgentWorker中expose_function的定义一致
const reportSink = window.__AEGIS_IAST_HOOK__;

if (reportSink) {
    let hookCount = 0;
    let skipCount = 0;
    
    // 动态检测 jQuery
    function detectjQuery() {
        // 检查多种可能的jQuery存在方式
        const jQueryVariants = [
            window.jQuery,
            window.$,
            window.jquery,
            typeof jQuery !== 'undefined' ? jQuery : null,
            typeof $ !== 'undefined' ? $ : null
        ];
        
        for (const jq of jQueryVariants) {
            if (jq && jq.fn && typeof jq.fn === 'object') {
                return jq.fn;
            }
        }
        return null;
    }
    
    const jQueryFn = detectjQuery();
    
    // 设置jQuery对象
    for (const [name, sink] of Object.entries(sinks)) {
        if (sink.jquery && jQueryFn) {
            sink.obj = jQueryFn;
        }
    }
    
    for (const [name, sink] of Object.entries(sinks)) {
        try {
            // 检查可选的sink是否存在
            if (sink.optional && (!sink.obj || !sink.obj[sink.prop])) {
                skipCount++;
                continue;
            }
            
            if (!sink.obj) {
                console.warn(`Aegis: Skipping ${name} - object not found`);
                skipCount++;
                continue;
            }
            
            if (sink.type === 'property') {
                const originalDescriptor = Object.getOwnPropertyDescriptor(sink.obj, sink.prop);
                if (originalDescriptor && originalDescriptor.set) {
                    const originalSetter = originalDescriptor.set;
                    Object.defineProperty(sink.obj, sink.prop, {
                        set: function (value) {
                            // 检查值是否可疑
                            const strValue = String(value);
                            const isSuspicious = 
                                strValue.includes('javascript:') ||
                                strValue.includes('<script') ||
                                strValue.includes('onerror=') ||
                                strValue.includes('onload=') ||
                                strValue.includes('eval(') ||
                                strValue.length > 100;
                            
                            if (isSuspicious) {
                                // 将捕获到的值报告给Python端
                                reportSink({ 
                                    sink: name, 
                                    value: strValue.substring(0, 500),
                                    risk: sink.risk,
                                    stack: new Error().stack
                                });
                            }
                            // 调用原始的setter，以保证页面功能正常
                            return originalSetter.apply(this, arguments);
                        },
                        get: originalDescriptor.get,
                        configurable: true
                    });
                    hookCount++;
                }
            } else if (sink.type === 'function') {
                const originalFunction = sink.obj[sink.prop];
                if (originalFunction) {
                    sink.obj[sink.prop] = function (...args) {
                        // 对于特定函数，只在参数是字符串时报告
                        if (sink.checkString && args.length > 0 && typeof args[0] !== 'string') {
                            return originalFunction.apply(this, args);
                        }
                        
                        // 构建报告信息
                        const value = args.length > 0 ? String(args[0]).substring(0, 500) : '';
                        
                        // 检查是否可疑
                        const isSuspicious = 
                            value.includes('javascript:') ||
                            value.includes('eval(') ||
                            value.includes('<script') ||
                            (sink.checkString && typeof args[0] === 'string') ||
                            (name === 'eval' || name === 'Function');
                        
                        if (isSuspicious) {
                            reportSink({ 
                                sink: name, 
                                value: value,
                                risk: sink.risk,
                                argCount: args.length,
                                stack: new Error().stack
                            });
                        }
                        
                        // 调用原始的函数
                        return originalFunction.apply(this, args);
                    };
                    hookCount++;
                }
            } else if (sink.type === 'constructor') {
                // 处理构造函数（如Function）
                const OriginalConstructor = sink.obj[sink.prop];
                if (OriginalConstructor) {
                    sink.obj[sink.prop] = new Proxy(OriginalConstructor, {
                        construct: function(target, args) {
                            const value = args.length > 0 ? String(args[0]).substring(0, 500) : '';
                            reportSink({ 
                                sink: name, 
                                value: value,
                                risk: sink.risk,
                                type: 'constructor',
                                stack: new Error().stack
                            });
                            return new target(...args);
                        },
                        apply: function(target, thisArg, args) {
                            const value = args.length > 0 ? String(args[0]).substring(0, 500) : '';
                            reportSink({ 
                                sink: name, 
                                value: value,
                                risk: sink.risk,
                                type: 'function-call',
                                stack: new Error().stack
                            });
                            return target.apply(thisArg, args);
                        }
                    });
                    hookCount++;
                }
            }
        } catch (e) {
            console.error(`Aegis IAST Hook在劫持 ${name} 时失败:`, e);
        }
    }
    
    console.log(`Aegis IAST Hook注入完成：${hookCount} 个hooks成功，${skipCount} 个跳过。`);
    
    // 检测jQuery状态
    if (jQueryFn) {
        console.log('Aegis: jQuery检测成功，已hook jQuery方法');
    } else {
        console.log('Aegis: 未检测到jQuery');
    }
    
    // 监听XHR请求
    const originalXHROpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
        this._aegisURL = url;
        this._aegisMethod = method;
        return originalXHROpen.apply(this, [method, url, ...rest]);
    };
    
    const originalXHRSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(data) {
        if (this._aegisURL && (this._aegisURL.includes('http://') || 
            this._aegisURL.includes('file://') || 
            this._aegisURL.includes('javascript:'))) {
            reportSink({
                sink: 'XMLHttpRequest',
                value: this._aegisURL,
                risk: 'Suspicious XHR Request',
                method: this._aegisMethod,
                data: data ? String(data).substring(0, 200) : null
            });
        }
        return originalXHRSend.apply(this, arguments);
    };
    
    // 监听fetch请求
    if (window.fetch) {
        const originalFetch = window.fetch;
        window.fetch = function(url, options) {
            const urlStr = String(url);
            // 检查更多可疑模式
            if (urlStr.includes('javascript:') || 
                urlStr.includes('file://') ||
                urlStr.includes('data:') ||
                urlStr.includes('vbscript:') ||
                (options && options.credentials === 'include')) {
                reportSink({
                    sink: 'fetch',
                    value: urlStr,
                    risk: 'Suspicious Fetch Request',
                    method: options?.method || 'GET',
                    credentials: options?.credentials,
                    options: options ? JSON.stringify(options).substring(0, 200) : null
                });
            }
            return originalFetch.apply(this, arguments);
        };
    }
    
    // 监听WebSocket连接
    if (window.WebSocket) {
        const originalWebSocket = window.WebSocket;
        window.WebSocket = function(url, protocols) {
            reportSink({
                sink: 'WebSocket',
                value: url,
                risk: 'WebSocket Connection',
                protocols: protocols
            });
            return new originalWebSocket(url, protocols);
        };
    }
    
    // 监听EventSource (Server-Sent Events)
    if (window.EventSource) {
        const originalEventSource = window.EventSource;
        window.EventSource = function(url, eventSourceInitDict) {
            reportSink({
                sink: 'EventSource',
                value: url,
                risk: 'SSE Connection',
                withCredentials: eventSourceInitDict?.withCredentials
            });
            return new originalEventSource(url, eventSourceInitDict);
        };
    }
    
    // 监听Worker创建
    if (window.Worker) {
        const originalWorker = window.Worker;
        window.Worker = function(scriptURL, options) {
            reportSink({
                sink: 'Worker',
                value: scriptURL,
                risk: 'Web Worker Creation',
                type: options?.type || 'classic'
            });
            return new originalWorker(scriptURL, options);
        };
    }
    
    // 监听动态import
    if (typeof import === 'function') {
        const originalImport = window.import || import;
        window.import = function(specifier) {
            reportSink({
                sink: 'import()',
                value: String(specifier),
                risk: 'Dynamic Import'
            });
            return originalImport.call(this, specifier);
        };
    }
    
} else {
    console.error("Aegis IAST Hook注入失败: 未找到回调函数。");
}
