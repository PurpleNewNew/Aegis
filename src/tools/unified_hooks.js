/**
 * Aegis Unified Hooks - 统一的JavaScript钩子脚本
 * 
 * 此文件合并了以下功能：
 * - IAST检测：检测XSS、危险函数调用等
 * - JS逆向：监控加密函数、网络请求等
 * 
 * 替代了原来的：
 * - js_hooks.js（已删除）
 * - js_reverse_hooks.js（已删除）
 * 
 * 避免了多个钩子脚本的冲突问题
 */
(() => {
    // 防止重复注入
    if (window.__aegis_unified_hooked) {
        return;
    }
    window.__aegis_unified_hooked = true;

    console.log("Aegis Unified hooks are being installed.");

    // 配置
    const config = {
        iast: {
            enabled: true,
            reportFunction: '__aegis_iast_report__'
        },
        jsReverse: {
            enabled: true,
            reportFunction: '__aegis_js_re_report__'
        }
    };

    // 统一的报告函数
    const report = (event, type) => {
        // 根据事件类型决定发送到哪个回调
        if (type === 'iast' && window[config.iast.reportFunction]) {
            window[config.iast.reportFunction]({
                ...event,
                reported_by: 'unified_hooks'
            });
        } else if (type === 'js_reverse' && window[config.jsReverse.reportFunction]) {
            window[config.jsReverse.reportFunction]({
                ...event,
                reported_by: 'unified_hooks'
            });
        } else {
            console.warn(`Aegis Unified: Report function not found for type: ${type}`, event);
        }
    };

    // ========== IAST相关钩子 ==========
    if (config.iast.enabled) {
        // 1. Hook for innerHTML
        const originalInnerHTMLSetter = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML').set;
        Object.defineProperty(Element.prototype, 'innerHTML', {
            set: function (value) {
                if (typeof value === 'string' && value.match(/<script/i)) {
                    report({
                        type: 'iast_event',
                        sink: 'innerHTML',
                        value: value.substring(0, 100),
                        url: window.location.href,
                        description: 'Potential XSS: A script tag was inserted into innerHTML.'
                    }, 'iast');
                }
                return originalInnerHTMLSetter.call(this, value);
            }
        });

        // 2. Hook for eval()
        const originalEval = window.eval;
        window.eval = function(str) {
            report({
                type: 'iast_event',
                sink: 'eval',
                value: str.substring(0, 100),
                url: window.location.href,
                description: 'Dangerous Function Call: eval() was used.'
            }, 'iast');
            return originalEval.apply(this, arguments);
        };

        // 3. Hook for document.write
        const originalDocumentWrite = document.write;
        document.write = function(str) {
            if (typeof str === 'string' && str.match(/<script/i)) {
                report({
                    type: 'iast_event',
                    sink: 'document.write',
                    value: str.substring(0, 100),
                    url: window.location.href,
                    description: 'Potential XSS: document.write() with script content.'
                }, 'iast');
            }
            return originalDocumentWrite.apply(this, arguments);
        };

        // 4. Hook for setTimeout/setInterval
        const originalSetTimeout = window.setTimeout;
        window.setTimeout = function(callback, delay, ...args) {
            if (typeof callback === 'string' && callback.match(/<script/i)) {
                report({
                    type: 'iast_event',
                    sink: 'setTimeout',
                    value: callback.substring(0, 100),
                    url: window.location.href,
                    description: 'Potential XSS: setTimeout() with script string.'
                }, 'iast');
            }
            return originalSetTimeout.call(this, callback, delay, ...args);
        };

        const originalSetInterval = window.setInterval;
        window.setInterval = function(callback, delay, ...args) {
            if (typeof callback === 'string' && callback.match(/<script/i)) {
                report({
                    type: 'iast_event',
                    sink: 'setInterval',
                    value: callback.substring(0, 100),
                    url: window.location.href,
                    description: 'Potential XSS: setInterval() with script string.'
                }, 'iast');
            }
            return originalSetInterval.call(this, callback, delay, ...args);
        };
    }

    // ========== JS逆向相关钩子 ==========
    if (config.jsReverse.enabled) {
        // 钩子函数，用于包装原生函数以捕获调用信息
        const createHook = (obj, funcName, eventCategory) => {
            if (!obj || !obj[funcName]) return;

            const originalFunc = obj[funcName];
            obj[funcName] = function(...args) {
                // 记录函数调用
                report({
                    type: 'function_call',
                    category: eventCategory,
                    functionName: funcName,
                    args: args.map(arg => 
                        typeof arg === 'string' || typeof arg === 'number' || typeof arg === 'boolean' 
                            ? String(arg).substring(0, 500) 
                            : typeof arg
                    ),
                    timestamp: Date.now(),
                    url: window.location.href
                }, 'js_reverse');

                // 调用原始函数
                const result = originalFunc.apply(this, args);
                
                // 记录返回值
                if (result !== undefined) {
                    report({
                        type: 'function_return',
                        category: eventCategory,
                        functionName: funcName,
                        result: typeof result === 'string' || typeof result === 'number' || typeof result === 'boolean'
                            ? String(result).substring(0, 500)
                            : typeof result,
                        timestamp: Date.now(),
                        url: window.location.href
                    }, 'js_reverse');
                }

                return result;
            };

            // 保存原始函数引用
            obj[funcName].__aegis_original__ = originalFunc;
        };

        // 监控原生加密/编码函数
        const cryptoFunctions = [
            { obj: window, name: 'atob', category: 'encoding' },
            { obj: window, name: 'btoa', category: 'encoding' },
            { obj: window, name: 'eval', category: 'dangerous' },  // 同时被IAST和JS逆向监控
            { obj: window, name: 'Function', category: 'dangerous' },
            { obj: window, name: 'setTimeout', category: 'timing' },
            { obj: window, name: 'setInterval', category: 'timing' }
        ];

        cryptoFunctions.forEach(({obj, name, category}) => {
            createHook(obj, name, category);
        });

        // 监控XMLHttpRequest/Fetch
        const originalXHROpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url, ...args) {
            this.__aegis_url__ = url;
            this.__aegis_method__ = method;
            return originalXHROpen.call(this, method, url, ...args);
        };

        const originalXHRSend = XMLHttpRequest.prototype.send;
        XMLHttpRequest.prototype.send = function(data) {
            if (this.__aegis_url__) {
                report({
                    type: 'network_request',
                    category: 'xhr',
                    method: this.__aegis_method__,
                    url: this.__aegis_url__,
                    data: data ? String(data).substring(0, 500) : null,
                    timestamp: Date.now(),
                    page_url: window.location.href
                }, 'js_reverse');
            }
            return originalXHRSend.call(this, data);
        };

        // 监控Fetch API
        const originalFetch = window.fetch;
        window.fetch = function(input, init) {
            const url = typeof input === 'string' ? input : input.url;
            const method = (init && init.method) || 'GET';
            const data = init && init.body;
            
            report({
                type: 'network_request',
                category: 'fetch',
                method: method,
                url: url,
                data: data ? String(data).substring(0, 500) : null,
                timestamp: Date.now(),
                page_url: window.location.href
            }, 'js_reverse');

            return originalFetch.apply(this, arguments);
        };

        // 监控常见的加密函数（通过全局变量检测）
        const monitorCryptoFunctions = () => {
            const cryptoPatterns = ['encrypt', 'decrypt', 'encode', 'decode', 'hash', 'md5', 'sha', 'aes', 'rsa', 'base64'];
            
            // 遍历window对象
            for (const key in window) {
                if (typeof window[key] === 'function') {
                    const lowerKey = key.toLowerCase();
                    if (cryptoPatterns.some(pattern => lowerKey.includes(pattern))) {
                        // 如果还没有被钩子
                        if (!window[key].__aegis_hooked__) {
                            createHook(window, key, 'crypto');
                            window[key].__aegis_hooked__ = true;
                        }
                    }
                }
            }
        };

        // 立即执行一次
        monitorCryptoFunctions();
        
        // 定期检查新添加的函数
        setInterval(monitorCryptoFunctions, 5000);
    }

    // ========== 事件监听器增强 ==========
    // 增强的事件监听器，用于捕获更多信息
    const originalAddEventListener = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function(type, listener, options) {
        const wrappedListener = function(event) {
            // 报告事件触发
            if (config.jsReverse.enabled) {
                report({
                    type: 'event_triggered',
                    eventType: type,
                    target: event.target ? event.target.tagName + (event.target.id ? '#' + event.target.id : '') : 'unknown',
                    timestamp: Date.now(),
                    url: window.location.href
                }, 'js_reverse');
            }
            
            // 调用原始监听器
            return listener.apply(this, arguments);
        };

        // 保存原始监听器引用
        wrappedListener.__aegis_original__ = listener;
        
        return originalAddEventListener.call(this, type, wrappedListener, options);
    };

    console.log("Aegis Unified hooks installation completed.");
})();