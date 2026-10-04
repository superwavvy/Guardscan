// guardscan-patch.js (CommonJS)
//
// Fixes from the Juice Shop validation run:
//   1) SQL rule: real SQL structure + interpolation OR concatenation, ignores log calls
//   2) Verify LLM findings against the actual file (kills hallucinated lines like app.ts:15)
//   3) Test/config files: skip the LLM, cap severity
//   4) Prompt addendum (frontend route guards)
//
// QUICK TEST ON YOUR PHONE:   node guardscan-patch.js
//
// WIRING (inside your per-file loop in scanner.js):
//
//   const P = require('./guardscan-patch');
//
//   // a) Replace your OLD SQL regex rule with this:
//   const patternFindings = [
//     ...P.detectSqlInjection(f.content),
//     // ...your other pattern rules (secrets, http urls, etc.)
//   ];
//
//   // b) Skip the LLM for test/config files (pattern layer still runs):
//   const analyze = P.shouldSendToLLM(f.path) ? analyzeChunk : async () => [];
//
//   // c) After scanFileResilient(...) and BEFORE your dedupe/corroboration:
//   r.findings = P.applyVerification(r.findings, f.content);
//
//   // d) After dedupe/corroboration:
//   r.findings = P.adjustForNonProd(r.findings, f.path);
//
//   // e) Append P.PROMPT_ADDENDUM to the end of your LLM prompt.
//
// NOTE: pattern findings must have source: 'pattern' (this file sets it).
// LLM findings must NOT be tagged 'pattern' or 'both' before step (c).

// ---------- 1) SQL injection rule ----------

const LOG_CALL = /\b(logger|console|log)\.(error|warn|info|debug|log|trace)\s*\(/i;
const COMMENT = /^\s*(\/\/|\/\*|\*|#)/;
const INTERP = /\$\{[^}]+\}/;
// "..."+x+"..."  or  x+"..."
const CONCAT = /["'`]\s*\+\s*[A-Za-z_$(]|[A-Za-z_$)\]]\s*\+\s*["'`]/;
const SQL_STRUCT =
  /\b(SELECT\s[\s\S]{1,300}?\bFROM\b|INSERT\s+INTO\b|UPDATE\s+[\w.`"\[\]]+\s+SET\b|DELETE\s+FROM\b)/i;
const SQL_CONTEXT =
  /\b(WHERE|JOIN|ORDER\s+BY|GROUP\s+BY|LIMIT|VALUES)\b|\b(query|execute|exec|raw|prepare)\s*\(/i;
// Parameterized usage nearby = probably safe
const PARAMETERIZED = /\b(replacements|bind)\s*:/i;

function detectSqlInjection(content) {
  const lines = content.split('\n');
  const findings = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (COMMENT.test(line) || LOG_CALL.test(line)) continue;

    // The line itself must interpolate or concatenate something
    if (!INTERP.test(line) && !CONCAT.test(line)) continue;

    // SQL structure can span a few lines (multi-line template strings)
    const windowText = lines.slice(Math.max(0, i - 2), i + 3).join(' ');
    if (!SQL_STRUCT.test(windowText)) continue;
    if (!SQL_CONTEXT.test(windowText)) continue;
    if (PARAMETERIZED.test(windowText)) continue;

    findings.push({
      file: undefined, // caller fills in
      line: i + 1,
      type: 'SQL Injection',
      severity: 'HIGH',
      confidence: 'HIGH',
      cwe_id: 'CWE-89',
      owasp_category: 'A05:2025',
      source: 'pattern',
      description:
        'SQL query built with string interpolation or concatenation. User-controlled input could alter the query.',
      code_snippet: line.trim().slice(0, 200),
      fix: 'Use parameterized queries (placeholders / replacements / bind) instead of building SQL strings.',
    });
  }
  return findings;
}

// ---------- 2) Verify LLM findings against the real file ----------

const normalize = (s) =>
  String(s || '').replace(/\s+/g, ' ').trim().toLowerCase();

function cleanSnippet(snippet) {
  // We send numbered lines ("42: code"), so models often echo the prefix back
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
  if (!cleaned) return { ok: false, reason: 'no code_snippet' };

  // Probe with the first line of the snippet (models often mangle the tail)
  const probe = normalize(cleaned.split('\n')[0]).slice(0, 60);
  if (probe.length < 8) return { ok: false, reason: 'snippet too short to verify' };

  const from = Math.max(0, line - 1 - radius);
  const to = Math.min(lines.length, line + radius);
  const windowText = normalize(lines.slice(from, to).join(' '));

  return windowText.includes(probe)
    ? { ok: true }
    : { ok: false, reason: 'snippet not found near reported line' };
}

// Pattern findings are exact by construction, so they skip verification.
// Unverified LLM findings are downgraded to LOW confidence (or dropped).
function applyVerification(findings, content, { dropUnverified = false } = {}) {
  const lines = content.split('\n');
  const out = [];

  for (const f of findings) {
    if (f.source === 'pattern' || f.source === 'both') {
      out.push(f);
      continue;
    }
    const v = verifyFinding(f, lines);
    if (v.ok) {
      out.push({ ...f, verified: true });
    } else if (!dropUnverified) {
      out.push({ ...f, verified: false, confidence: 'LOW', verify_note: v.reason });
    }
  }
  return out;
}

// ---------- 3) Test / config / challenge files ----------
// "codefixes" is Juice Shop specific (deliberately vulnerable training snippets).
// Remove it from the regex if you don't want that behavior for other repos.

const NON_PROD =
  /(^|\/)(test|tests|__tests__|spec|e2e|cypress|fixtures?|mocks?|examples?|docs?|codefixes)(\/|$)|\.(test|spec)\.[jt]sx?$|(^|\/)[^/]*\.config\.[jt]s$/i;

const isNonProd = (path) => NON_PROD.test(path);

const shouldSendToLLM = (path, { includeNonProd = false } = {}) =>
  includeNonProd || !isNonProd(path);

function adjustForNonProd(findings, path) {
  if (!isNonProd(path)) return findings;
  return findings.map((f) => ({
    ...f,
    severity: 'LOW',
    note: 'test/config/example code: severity capped',
  }));
}

// ---------- 4) Prompt addendum ----------

const PROMPT_ADDENDUM = `
Additional rules:
- In frontend routing files (Angular/React/Vue routes), do NOT report "missing route guard" as an access control vulnerability. Real access control is enforced server-side.
- Always include "code_snippet" containing the exact line of code (without the line-number prefix) that you are reporting.
- Do not report issues in test files, mocks, or configuration for test tooling.
`;

// ---------- Self-test ----------

function selfTest() {
  const cases = [
    {
      name: 'log with ${} (datacreator.ts:147)',
      code: 'logger.error(`Could not bulk insert Challenges: ${utils.getErrorMessage(err)}`)',
      expect: false,
    },
    {
      name: 'log with ${} (datacreator.ts:210)',
      code: 'logger.error(`Could not insert User ${key}: ${utils.getErrorMessage(err)}`)',
      expect: false,
    },
    {
      name: 'plain seed data (datacreator.ts:274)',
      code: 'cardNum: Number(card.cardNum),',
      expect: false,
    },
    {
      name: 'concatenation (dbSchemaChallenge_1)',
      code: `models.sequelize.query("SELECT * FROM Products WHERE ((name LIKE '%"+criteria+"%' OR description LIKE '%"+criteria+"%') AND deletedAt IS NULL) ORDER BY name")`,
      expect: true,
    },
    {
      name: 'template literal (dbSchemaChallenge_3)',
      code: 'models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE \'%${criteria}%\' OR description LIKE \'%${criteria}%\') AND deletedAt IS NULL) ORDER BY name`)',
      expect: true,
    },
    {
      name: 'parameterized query (should NOT flag)',
      code: "db.query('SELECT * FROM users WHERE id = $1', [id])",
      expect: false,
    },
    {
      name: 'sequelize replacements (should NOT flag)',
      code: "models.sequelize.query('SELECT * FROM Products WHERE name = :name', { replacements: { name } })",
      expect: false,
    },
  ];

  let pass = 0;
  for (const c of cases) {
    const got = detectSqlInjection(c.code).length > 0;
    const ok = got === c.expect;
    if (ok) pass++;
    console.log(`${ok ? '✅' : '❌'} ${c.name} -> flagged: ${got} (expected ${c.expect})`);
  }

  // Verification checks
  const file = ['const a = 1;', 'app.use(cookieParser(\'kekse\'))', 'const b = 2;'].join('\n');
  const lines = file.split('\n');
  const good = verifyFinding({ line: 2, code_snippet: "2: app.use(cookieParser('kekse'))" }, lines);
  const bad = verifyFinding({ line: 15, code_snippet: 'catch (e) { throw e }' }, lines);
  const wrongLine = verifyFinding({ line: 3, code_snippet: "app.use(cookieParser('kekse'))" }, lines);
  console.log(`${good.ok ? '✅' : '❌'} verify: correct line passes`);
  console.log(`${!bad.ok ? '✅' : '❌'} verify: out-of-range line rejected (${bad.reason})`);
  console.log(`${wrongLine.ok ? '✅' : '❌'} verify: off-by-one within radius passes`);

  // Non-prod checks
  const np = [
    ['cypress.config.ts', true],
    ['data/static/codefixes/adminSectionChallenge_1_correct.ts', true],
    ['routes/login.ts', false],
    ['lib/insecurity.ts', false],
  ];
  for (const [p, exp] of np) {
    const got = isNonProd(p);
    console.log(`${got === exp ? '✅' : '❌'} nonProd(${p}) = ${got}`);
  }

  console.log(`\n${pass}/${cases.length} SQL rule cases passed`);
}

module.exports = {
  detectSqlInjection,
  verifyFinding,
  applyVerification,
  isNonProd,
  shouldSendToLLM,
  adjustForNonProd,
  PROMPT_ADDENDUM,
};

if (require.main === module) selfTest();

