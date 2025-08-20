/**
 * Aegis IAST Hooks - a set of JavaScript hooks to detect dangerous operations in real-time.
 */
(() => {
    if (window.__aegis_iast_hooked) {
        return;
    }
    window.__aegis_iast_hooked = true;

    console.log("Aegis IAST hooks are being installed.");

    // The callback function exposed by Playwright
    const reportFinding = (finding) => {
        if (window.__aegis_iast_report__) {
            window.__aegis_iast_report__(finding);
        } else {
            console.warn("Aegis IAST: Report function not found.", finding);
        }
    };

    // 1. Hook for innerHTML
    const originalInnerHTMLSetter = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML').set;

    Object.defineProperty(Element.prototype, 'innerHTML', {
        set: function (value) {
            if (typeof value === 'string' && value.match(/<script/i)) {
                reportFinding({
                    type: 'iast_event',
                    sink: 'innerHTML',
                    value: value.substring(0, 100), // Report a snippet
                    url: window.location.href,
                    description: 'Potential XSS: A script tag was inserted into innerHTML.'
                });
            }
            return originalInnerHTMLSetter.call(this, value);
        }
    });

    // 2. Hook for eval()
    const originalEval = window.eval;
    window.eval = function(str) {
        reportFinding({
            type: 'iast_event',
            sink: 'eval',
            value: str.substring(0, 100),
            url: window.location.href,
            description: 'Dangerous Function Call: eval() was used.'
        });
        return originalEval.apply(this, arguments);
    };

    // 3. Hook for document.write()
    const originalDocWrite = document.write;
    document.write = function(str) {
        if (typeof str === 'string' && str.match(/<script/i)) {
            reportFinding({
                type: 'iast_event',
                sink: 'document.write',
                value: str.substring(0, 100),
                url: window.location.href,
                description: 'Potential XSS: A script tag was passed to document.write().'
            });
        }
        return originalDocWrite.apply(this, arguments);
    };

    console.log("Aegis IAST hooks installed successfully.");
})();