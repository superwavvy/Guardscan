// ---------- 1) SQL injection rule ----------
const LOG_CALL = /\b(logger|console|log)\.(error|warn|info|debug|log|trace)\s*\(/i;
const COMMENT = /^\s*(\/\/|\/\*|\*|#)/;
const INTERP = /\$\{[^}]+\}/;
const CONCAT = /["'`]\s*\+\s*[A-Za-z_$(]|[A-Za-z_$)\]]\s*\+\s*["'`]/;
const SQL_STRUCT = /\b(SELECT\s[\s\S]{1,300}?\bFROM\b|INSERT\s+INTO\b|UPDATE\s+[\w.`"\[\]]+\s+SET\b|DELETE\s+FROM\b)/i;
const SQL_CONTEXT = /\b(WHERE|JOIN|ORDER\s+BY|GROUP\s+BY|LIMIT|VALUES)\b|\b(query|execute|exec|raw|prepare)\s*\(/i;
const PARAMETERIZED = /\b(replacements|bind)\s*:/i;

function detectSqlInjection(content) {
  const lines = content.split('\n');
  const findings = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (COMMENT.test(line) || LOG_CALL.test(line)) continue;
    if (!INTERP.test(line) && !CONCAT.test(line)) continue;

    const windowText = lines.slice(Math.max(0, i - 2), i + 3).join(' ');
    if (!SQL_STRUCT.test(windowText)) continue;
    if (!SQL_CONTEXT.test(windowText)) continue;
    if (PARAMETERIZED.test(windowText)) continue;

    findings.push({
      file: undefined,
      line: i + 1,
      type: 'SQL Injection',
      severity: 'HIGH',
      confidence: 'HIGH',
      cwe_id: 'CWE-89',
      owasp_category: 'A05:2025',
      source: 'pattern',
      description: 'SQL query built with string interpolation or concatenation. User-controlled input could alter the query.',
      code_snippet: line.trim().slice(0, 200),
      fix: 'Use parameterized queries (placeholders / replacements / bind) instead of building SQL strings.',
    });
  }
  return findings;
}

// ---------- 2) Two-tier verification ----------

// Strict types require an exact snippet match near the reported line.
// Design-level types get relaxed verification because the "issue" spans the handler.
const STRICT_TYPES = [
  'sql injection', 'nosql injection', 'command injection', 'code injection',
  'xss', 'cross-site scripting', 'hardcoded credential', 'hardcoded secret',
  'path traversal', 'ssrf', 'server-side request forgery',
  'insecure deserialization', 'prototype pollution', 'insecure eval',
  'unsafe dynamic require', 'http response splitting', 'insecure transport',
  'information exposure'
];

function isStrictType(type) {
  const t = String(type || '').toLowerCase();
  return STRICT_TYPES.some(s => t.includes(s));
}

const normalize = (s) => String(s || '').replace(/\s+/g, ' ').trim().toLowerCase();

function cleanSnippet(snippet) {
  return String(snippet || '')
    .replace(/(^|\n)\s*\d+:\s?/g, '$1')
    .trim();
}

function verifyFinding(finding, lines, radius = 3) {
  const line = Number(finding.line);
  if (!Number.isInteger(line) || line < 1 || line > lines.length) {
    return { ok: false, reason: 'line out of range' };
  }

  const cleaned = cleanSnippet(finding.code_snippet);
  if (!cleaned) {
    return isStrictType(finding.type)
      ? { ok: false, reason: 'no code_snippet' }
      : { ok: true, relaxed: true, reason: 'design-level: no snippet required' };
  }

  const probe = normalize(cleaned.split('\n')[0]).slice(0, 60);

  // Short snippets: strict types fail, design-level types pass
  if (probe.length < 8) {
    return isStrictType(finding.type)
      ? { ok: false, reason: 'snippet too short to verify' }
      : { ok: true, relaxed: true, reason: 'design-level: short snippet accepted' };
  }

  const from = Math.max(0, line - 1 - radius);
  const to = Math.min(lines.length, line + radius);
  const windowText = normalize(lines.slice(from, to).join(' '));

  if (windowText.includes(probe)) {
    return { ok: true };
  }

  // Design-level findings: accept if the line itself looks like real code
  if (!isStrictType(finding.type)) {
    const lineContent = normalize(lines[line - 1] || '');
    if (lineContent.length > 15) {
      return { ok: true, relaxed: true, reason: 'design-level: line exists with substantial code' };
    }
  }

  return { ok: false, reason: 'snippet not found near reported line' };
}

function applyVerification(findings, content, { dropUnverified = false, verbose = true } = {}) {
  const lines = content.split('\n');
  const out = [];
  let verified = 0, relaxed = 0, downgraded = 0, dropped = 0;

  for (const f of findings) {
    if (f.source === 'pattern' || f.source === 'both') {
      out.push(f);
      continue;
    }
    const v = verifyFinding(f, lines);
    if (v.ok) {
      out.push({ ...f, verified: !v.relaxed, verify_note: v.reason || null });
      if (v.relaxed) relaxed++; else verified++;
    } else if (!dropUnverified) {
      out.push({ ...f, verified: false, confidence: 'LOW', verify_note: v.reason });
      downgraded++;
      if (verbose) {
        console.log(`   ⚠️  Downgraded: ${f.type} @ ${f.file}:${f.line} — ${v.reason}`);
      }
    } else {
      dropped++;
      if (verbose) {
        console.log(`   🗑️  Dropped: ${f.type} @ ${f.file}:${f.line} — ${v.reason}`);
      }
    }
  }

  if (verbose && findings.length > 0) {
    console.log(`   📊 Verify: ${verified} strict, ${relaxed} relaxed, ${downgraded} downgraded, ${dropped} dropped`);
  }

  return out;
}

// ---------- 3) Non-prod files ----------
const NON_PROD = /(^|\/)(test|tests|__tests__|spec|e2e|cypress|fixtures?|mocks?|examples?|docs?|codefixes)(\/|$)|\.(test|spec)\.[jt]sx?$|(^|\/)[^/]*\.config\.[jt]s$/i;
const isNonProd = (path) => NON_PROD.test(path);
const shouldSendToLLM = (path, { includeNonProd = false } = {}) => includeNonProd || !isNonProd(path);
function adjustForNonProd(findings, path) {
  if (!isNonProd(path)) return findings;
  return findings.map((f) => ({ ...f, severity: 'LOW', note: 'test/config/example code: severity capped' }));
}

const PROMPT_ADDENDUM = `
Additional rules:
- In frontend routing files (Angular/React/Vue routes), do NOT report "missing route guard" as an access control vulnerability. Real access control is enforced server-side.
- Always include "code_snippet" containing the exact line of code (without the line-number prefix) that you are reporting.
- For design-level issues (authentication failures, missing authorization, insecure design), the code_snippet may be the handler signature or the route declaration line.
- Do not report issues in test files, mocks, or configuration for test tooling.
`;

module.exports = {
  detectSqlInjection,
  verifyFinding,
  applyVerification,
  isNonProd,
  shouldSendToLLM,
  adjustForNonProd,
  PROMPT_ADDENDUM,
  isStrictType,
};
