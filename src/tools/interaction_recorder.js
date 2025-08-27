/**
 * Aegis 交互录制器 - 完整记录用户操作序列
 */
(() => {
    if (window.__aegis_interaction_recorder) {
        return;
    }
    window.__aegis_interaction_recorder = true;
    
    console.log("Aegis交互录制器正在安装。");
    
    // 存储操作序列
    let interactionSequence = [];
    let isRecording = false;
    let recordingStartTime = null;
    
    // 生成唯一ID
    function generateId() {
        return Date.now().toString(36) + Math.random().toString(36).substr(2);
    }
    
    // 获取元素的完整路径
    function getElementPath(element) {
        if (!(element instanceof Element)) return '';
        
        let path = [];
        while (element.nodeType === Node.ELEMENT_NODE) {
            let selector = element.nodeName.toLowerCase();
            
            if (element.id) {
                selector += '#' + element.id;
                path.unshift(selector);
                break;
            } else {
                let sib = element, nth = 1;
                while (sib = sib.previousElementSibling) {
                    if (sib.nodeName.toLowerCase() == selector)
                        nth++;
                }
                if (nth != 1)
                    selector += ":nth-of-type(" + nth + ")";
            }
            
            path.unshift(selector);
            element = element.parentElement;
        }
        
        return path.join(' > ');
    }
    
    // 获取元素的所有属性
    function getElementAttributes(element) {
        const attrs = {};
        for (let i = 0; i < element.attributes.length; i++) {
            const attr = element.attributes[i];
            attrs[attr.name] = attr.value;
        }
        return attrs;
    }
    
    // 记录交互事件
    function recordInteraction(eventType, element, details = {}) {
        if (!isRecording) return;
        
        const interaction = {
            id: generateId(),
            timestamp: Date.now(),
            relativeTime: recordingStartTime ? Date.now() - recordingStartTime : 0,
            type: eventType,
            element: {
                selector: getElementPath(element),
                tagName: element.tagName.toLowerCase(),
                attributes: getElementAttributes(element),
                textContent: element.textContent?.trim().slice(0, 100) || '',
                value: element.value || '',
                checked: element.checked || false,
                selectedIndex: element.selectedIndex || -1
            },
            pageState: {
                url: window.location.href,
                title: document.title,
                readyState: document.readyState
            },
            details: details
        };
        
        // 捕获页面截图（通过CDP）
        if (window.__aegis_capture_screenshot__) {
            interaction.screenshotId = 'screenshot_' + interaction.id;
        }
        
        interactionSequence.push(interaction);
        
        // 发送到后端
        if (window.__aegis_report_interaction__) {
            window.__aegis_report_interaction__(interaction);
        }
        
        console.log('Aegis: 已记录交互', interaction);
    }
    
    // 监听所有交互事件
    function setupEventListeners() {
        // 点击事件
        document.addEventListener('click', (e) => {
            recordInteraction('click', e.target, {
                button: e.button,
                ctrlKey: e.ctrlKey,
                altKey: e.altKey,
                shiftKey: e.shiftKey,
                metaKey: e.metaKey,
                clientX: e.clientX,
                clientY: e.clientY
            });
        }, true);
        
        // 输入事件
        document.addEventListener('input', (e) => {
            const inputType = e.inputType;
            const data = e.data;
            
            recordInteraction('input', e.target, {
                inputType: inputType,
                data: data,
                value: e.target.value,
                selectionStart: e.target.selectionStart,
                selectionEnd: e.target.selectionEnd
            });
        }, true);
        
        // 键盘事件
        document.addEventListener('keydown', (e) => {
            if (e.key.length === 1 || e.key === 'Backspace' || e.key === 'Delete' || e.key === 'Enter') {
                recordInteraction('keydown', e.target, {
                    key: e.key,
                    code: e.code,
                    altKey: e.altKey,
                    ctrlKey: e.ctrlKey,
                    metaKey: e.metaKey,
                    shiftKey: e.shiftKey,
                    repeat: e.repeat
                });
            }
        }, true);
        
        // 焦点事件
        document.addEventListener('focus', (e) => {
            recordInteraction('focus', e.target, {});
        }, true);
        
        document.addEventListener('blur', (e) => {
            recordInteraction('blur', e.target, {
                value: e.target.value
            });
        }, true);
        
        // 表单事件
        document.addEventListener('change', (e) => {
            recordInteraction('change', e.target, {
                value: e.target.value,
                checked: e.target.checked
            });
        }, true);
        
        // 提交事件
        document.addEventListener('submit', (e) => {
            recordInteraction('submit', e.target, {
                action: e.target.action,
                method: e.target.method
            });
        }, true);
        
        // 自定义事件监听（用于React等框架）
        const originalDispatchEvent = EventTarget.prototype.dispatchEvent;
        EventTarget.prototype.dispatchEvent = function(event) {
            const result = originalDispatchEvent.call(this, event);
            
            // 监听特定的事件类型
            if (event.type.includes('click') || 
                event.type.includes('input') || 
                event.type.includes('change') ||
                event.type === 'submit') {
                setTimeout(() => {
                    recordInteraction('custom_' + event.type, event.target, {
                        eventType: event.type,
                        bubbles: event.bubbles,
                        cancelable: event.cancelable
                    });
                }, 0);
            }
            
            return result;
        };
    }
    
    // 开始录制
    window.startAegisRecording = function() {
        if (isRecording) return;
        
        isRecording = true;
        recordingStartTime = Date.now();
        interactionSequence = [];
        
        console.log('Aegis: 开始录制交互');
        
        // 发送开始事件
        if (window.__aegis_report_interaction__) {
            window.__aegis_report_interaction__({
                type: 'recording_started',
                timestamp: Date.now(),
                url: window.location.href
            });
        }
    };
    
    // 停止录制
    window.stopAegisRecording = function() {
        if (!isRecording) return;
        
        isRecording = false;
        
        console.log('Aegis: 停止录制。总交互数:', interactionSequence.length);
        
        // 发送结束事件和完整序列
        if (window.__aegis_report_interaction__) {
            window.__aegis_report_interaction__({
                type: 'recording_stopped',
                timestamp: Date.now(),
                sequence: interactionSequence,
                totalInteractions: interactionSequence.length
            });
        }
        
        return interactionSequence;
    };
    
    // 获取当前录制序列
    window.getAegisRecording = function() {
        return interactionSequence;
    };
    
    // 自动开始录制
    setupEventListeners();
    window.startAegisRecording();
    
    // 页面卸载时保存录制
    window.addEventListener('beforeunload', () => {
        if (isRecording && interactionSequence.length > 0) {
            if (window.__aegis_report_interaction__) {
                window.__aegis_report_interaction__({
                    type: 'page_unload',
                    timestamp: Date.now(),
                    sequence: interactionSequence
                });
            }
        }
    });
})();