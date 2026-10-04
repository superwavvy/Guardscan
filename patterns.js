const { detectSqlInjection } = require('./guardscan-patch.js');

// --- Deterministic Pattern Rules (run every time, no LLM needed) ---
const PATTERN_RULES = [
    // SQL Injection is handled separately via guardscan-patch.js detectSqlInjection()
    // (that rule needs multi-line context, so it can't be a simple regex)

    // ===== Code / Command Injection =====
    {
        id: "eval-usage",
        type: "Code Injection",
        severity: "HIGH",
        owasp_category: "A05:2025",
        cwe_id: "CWE-95",
        extensions: ["js", "ts", "jsx", "tsx"],
        pattern: /\beval\s*\(/g,
        description: "Use of eval() can execute arbitrary code.",
        fix: "Remove eval(). Use JSON.parse() for data or a safe parser."
    },
    {
        id: "child-process-exec",
        type: "Command Injection",
        severity: "HIGH",
        owasp_category: "A05:2025",
        cwe_id: "CWE-78",
        extensions: ["js", "ts", "jsx", "tsx"],
        pattern: /(?:child_process\.)?exec\s*\(\s*(?:`[^`]*\$\{|[^)]*\+)/g,
        description: "exec() called with dynamic input — shell injection risk.",
        fix: "Use execFile() with an argument array, or validate input strictly."
    },

    // ===== Hardcoded Secrets =====
    {
        id: "hardcoded-secret",
        type: "Hardcoded Credentials",
        severity: "HIGH",
        owasp_category: "A02:2025",
        cwe_id: "CWE-798",
        extensions: ["js", "ts", "jsx", "tsx", "py", "rb", "php"],
        pattern: /(?:password|passwd|pwd|secret|api[_-]?key|apikey|token|private[_-]?key)\s*[:=]\s*['"](?!\$\{)[^'"]{8,}['"]/gi,
        description: "Hardcoded credential or API key in source code.",
        fix: "Move to environment variables or a secret manager."
    },

    // ===== XSS =====
    {
        id: "innerhtml-assignment",
        type: "Cross-Site Scripting (XSS)",
        severity: "HIGH",
        owasp_category: "A05:2025",
        cwe_id: "CWE-79",
        extensions: ["js", "ts", "jsx", "tsx"],
        pattern: /\.innerHTML\s*=\s*(?!['"`][^'"`]*['"`]\s*;)/g,
        description: "Assignment to innerHTML can introduce XSS if the value is user-controlled.",
        fix: "Use textContent or sanitize with DOMPurify."
    },
    {
        id: "dangerously-set-innerhtml",
        type: "Cross-Site Scripting (XSS)",
        severity: "HIGH",
        owasp_category: "A05:2025",
        cwe_id: "CWE-79",
        extensions: ["js", "ts", "jsx", "tsx"],
        pattern: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/g,
        description: "dangerouslySetInnerHTML bypasses React's XSS protections.",
        fix: "Sanitize input with DOMPurify before passing it in."
    },

    // ===== Cryptographic Failures =====
    {
        id: "weak-hash",
        type: "Weak Cryptography",
        severity: "MEDIUM",
        owasp_category: "A04:2025",
        cwe_id: "CWE-327",
        extensions: ["js", "ts", "jsx", "tsx", "py", "rb", "php"],
        pattern: /createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)|hashlib\.(?:md5|sha1)\s*\(/gi,
        description: "MD5/SHA1 are cryptographically broken for security use.",
        fix: "Use SHA-256 for hashing, bcrypt/argon2 for passwords."
    },
    {
        id: "http-url",
        type: "Insecure Transport",
        severity: "LOW",
        owasp_category: "A04:2025",
        cwe_id: "CWE-319",
        extensions: ["js", "ts", "jsx", "tsx", "py"],
        pattern: /["']http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[^"']+["']/g,
        description: "Plain HTTP URL detected — data is transmitted unencrypted.",
        fix: "Use HTTPS instead of HTTP."
    },

    // ===== Security Misconfiguration =====
    {
        id: "cors-wildcard",
        type: "CORS Misconfiguration",
        severity: "MEDIUM",
        owasp_category: "A02:2025",
        cwe_id: "CWE-942",
        extensions: ["js", "ts", "jsx", "tsx", "py"],
        pattern: /Access-Control-Allow-Origin['"]?\s*[:=,]\s*['"]\*/g,
        description: "CORS wildcard allows any origin to access the resource.",
        fix: "Restrict allowed origins to a known whitelist."
    },
    {
        id: "debug-true",
        type: "Security Misconfiguration",
        severity: "MEDIUM",
        owasp_category: "A02:2025",
        cwe_id: "CWE-489",
        extensions: ["py"],
        pattern: /DEBUG\s*=\s*True/g,
        description: "Debug mode enabled — may leak sensitive info in error pages.",
        fix: "Set DEBUG = False in production."
    },

    // ===== Python-specific =====
    {
        id: "python-pickle",
        type: "Insecure Deserialization",
        severity: "HIGH",
        owasp_category: "A08:2025",
        cwe_id: "CWE-502",
        extensions: ["py"],
        pattern: /pickle\.loads?\s*\(/g,
        description: "pickle.loads() can execute arbitrary code from untrusted data.",
        fix: "Use JSON or another safe serialization format."
    }
];

// --- Helper: get file extension ---
function getExtension(filePath) {
    return filePath.split('.').pop().toLowerCase();
}

// --- Run all pattern rules against one file ---
function scanWithPatterns(filePath, content) {
    const ext = getExtension(filePath);
    const findings = [];
    const MAX_PER_RULE = 5;

    // SQL injection (multi-line aware, from guardscan-patch.js)
    const sqlFindings = detectSqlInjection(content);
    for (const f of sqlFindings) {
        findings.push({ ...f, file: filePath });
    }

    // Regex-based rules
    for (const rule of PATTERN_RULES) {
        if (!rule.extensions.includes(ext)) continue;

        const regex = new RegExp(rule.pattern.source, rule.pattern.flags);
        let match;
        let count = 0;

        while ((match = regex.exec(content)) !== null && count < MAX_PER_RULE) {
            const lineNum = content.substring(0, match.index).split('\n').length;

            const lineStart = content.lastIndexOf('\n', match.index) + 1;
            let lineEnd = content.indexOf('\n', match.index);
            if (lineEnd === -1) lineEnd = content.length;
            const lineText = content.substring(lineStart, lineEnd).trim();

            findings.push({
                file: filePath,
                line: lineNum,
                type: rule.type,
                owasp_category: rule.owasp_category,
                severity: rule.severity,
                confidence: "HIGH",
                cwe_id: rule.cwe_id,
                description: rule.description,
                code_snippet: lineText.slice(0, 200),
                fix: rule.fix,
                source: "pattern"
            });

            count++;
            if (match.index === regex.lastIndex) regex.lastIndex++;
        }
    }

    return findings;
}

module.exports = { scanWithPatterns, PATTERN_RULES };
