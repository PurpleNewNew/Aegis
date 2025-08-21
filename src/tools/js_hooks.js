/**
 * Aegis JS Reversing Hooks - 专门用于JavaScript逆向工程调试的钩子
 * 专注于捕获加密函数、网络请求和关键执行点
 */
(() => {
    // 防止重复注入
    if (window.__aegis_js_re_hooked) {
        return;
    }
    window.__aegis_js_re_hooked = true;

    console.log("Aegis JS Reversing hooks are being installed.");

    // 暴露给Playwright的回调函数
    const reportEvent = (event) => {
        if (window.__aegis_js_re_report__) {
            window.__aegis_js_re_report__(event);
        } else {
            console.warn("Aegis JS Re: Report function not found.", event);
        }
    };

    // 钩子函数，用于包装原生函数以捕获调用信息
    const createHook = (obj, funcName, eventCategory) => {
        if (!obj || !obj[funcName]) return;

        const originalFunc = obj[funcName];
        obj[funcName] = function(...args) {
            // 记录函数调用
            reportEvent({
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
            });

            // 调用原始函数
            const result = originalFunc.apply(this, args);
            
            // 记录返回值（如果需要）
            if (result !== undefined) {
                reportEvent({
                    type: 'function_return',
                    category: eventCategory,
                    functionName: funcName,
                    result: typeof result === 'string' || typeof result === 'number' || typeof result === 'boolean' 
                        ? String(result).substring(0, 500) 
                        : typeof result,
                    timestamp: Date.now()
                });
            }
            
            return result;
        };
    };

    // 1. Hook常见的加密函数
    const cryptoFunctions = [
        'encrypt', 'decrypt', 'sign', 'verify', 'hash', 'digest',
        'btoa', 'atob', 'encodeURIComponent', 'decodeURIComponent'
    ];
    
    cryptoFunctions.forEach(funcName => {
        createHook(window, funcName, 'crypto');
    });

    // 2. Hook JSON方法，用于捕获数据序列化/反序列化
    createHook(JSON, 'stringify', 'data');
    createHook(JSON, 'parse', 'data');

    // 3. Hook网络请求方法
    // XMLHttpRequest
    const originalXHROpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url, ...rest) {
        this._aegisMethod = method;
        this._aegisURL = url;
        reportEvent({
            type: 'xhr_open',
            method: method,
            url: url,
            timestamp: Date.now(),
            pageUrl: window.location.href
        });
        return originalXHROpen.apply(this, [method, url, ...rest]);
    };

    const originalXHRSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(body) {
        reportEvent({
            type: 'xhr_send',
            method: this._aegisMethod,
            url: this._aegisURL,
            body: body ? String(body).substring(0, 1000) : '',
            timestamp: Date.now(),
            pageUrl: window.location.href
        });
        return originalXHRSend.apply(this, [body]);
    };

    // Fetch API
    if (window.fetch) {
        const originalFetch = window.fetch;
        window.fetch = function(input, init) {
            const url = typeof input === 'string' ? input : input.url;
            const method = (init && init.method) || (typeof input !== 'string' && input.method) || 'GET';
            
            reportEvent({
                type: 'fetch_request',
                method: method,
                url: url,
                body: init && init.body ? String(init.body).substring(0, 1000) : '',
                headers: init && init.headers ? JSON.stringify(init.headers) : '{}',
                timestamp: Date.now(),
                pageUrl: window.location.href
            });

            const promise = originalFetch.apply(this, [input, init]);
            
            // 捕获响应
            promise.then(response => {
                reportEvent({
                    type: 'fetch_response',
                    url: url,
                    status: response.status,
                    statusText: response.statusText,
                    timestamp: Date.now()
                });
                return response;
            }).catch(error => {
                reportEvent({
                    type: 'fetch_error',
                    url: url,
                    error: String(error).substring(0, 500),
                    timestamp: Date.now()
                });
                throw error;
            });
            
            return promise;
        };
    }

    // 4. Hook eval和Function构造函数
    const originalEval = window.eval;
    window.eval = function(script) {
        reportEvent({
            type: 'eval',
            script: String(script).substring(0, 500),
            timestamp: Date.now(),
            pageUrl: window.location.href
        });
        return originalEval.apply(this, [script]);
    };

    const originalFunction = window.Function;
    window.Function = function(...args) {
        reportEvent({
            type: 'function_constructor',
            args: args.map(arg => String(arg).substring(0, 200)),
            timestamp: Date.now(),
            pageUrl: window.location.href
        });
        return originalFunction.apply(this, args);
    };

    // 5. Hook setInterval和setTimeout，用于捕获定时执行的代码
    const originalSetTimeout = window.setTimeout;
    window.setTimeout = function(handler, timeout, ...args) {
        if (typeof handler === 'string') {
            reportEvent({
                type: 'setTimeout_string',
                handler: handler.substring(0, 500),
                timeout: timeout,
                timestamp: Date.now(),
                pageUrl: window.location.href
            });
        }
        return originalSetTimeout.apply(this, [handler, timeout, ...args]);
    };

    const originalSetInterval = window.setInterval;
    window.setInterval = function(handler, timeout, ...args) {
        if (typeof handler === 'string') {
            reportEvent({
                type: 'setInterval_string',
                handler: handler.substring(0, 500),
                timeout: timeout,
                timestamp: Date.now(),
                pageUrl: window.location.href
            });
        }
        return originalSetInterval.apply(this, [handler, timeout, ...args]);
    };

    console.log("Aegis JS Reversing hooks installed successfully.");
})();