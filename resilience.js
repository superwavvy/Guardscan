// resilience.js — helpers for GuardScan (CommonJS)
//
// HOW TO WIRE IT IN (scanner.js):
//
//   const R = require('./resilience');
//
//   // 1) In your Groq call, attach status + retry-after to errors:
//   //    if (!res.ok) {
//   //      const e = new Error(`Groq API error: ${res.status}`);
//   //      e.status = res.status;
//   //      e.retryAfter = res.headers.get('retry-after');
//   //      throw e;
//   //    }
//
//   // 2) analyzeChunk(numberedText, startLine, path) must return an
//   //    ARRAY of findings (parsed JSON .vulnerabilities, or []).
//
//   // 3) Main loop:
//   //    const breaker = new R.CircuitBreaker();
//   //    const results = [];
//   //    for (const f of R.prioritizeFiles(files)) {
//   //      const patternFindings = runPatternLayer(f.path, f.content);
//   //      const r = await R.scanFileResilient({
//   //        path: f.path, content: f.content,
//   //        patternFindings, analyzeChunk, breaker,
//   //      });
//   //      results.push(r);
//   //      if (r.aborted) break;
//   //    }
//   //    R.printCoverage(results);

const MAX_CHUNK_TOKENS = 2000;
const MAX_CHUNKS_PER_FILE = 4;
const CHUNK_OVERLAP_LINES = 15;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const estimateTokens = (text) => Math.ceil(text.length / 4);

// ---------- Chunking (keeps REAL line numbers) ----------

function chunkFile(
  content,
  maxTokens = MAX_CHUNK_TOKENS,
  overlap = CHUNK_OVERLAP_LINES
) {
  const lines = content.split('\n');
  const maxLineChars = maxTokens * 4;
  const chunks = [];
  let start = 0;

  while (start < lines.length) {
    let end = start;
    let tokens = 0;
    const out = [];

    while (end < lines.length) {
      let line = lines[end];
      // Minified / huge single lines: truncate so they can't blow the limit
      if (line.length > maxLineChars) {
        line = line.slice(0, maxLineChars) + ' ...[truncated]';
      }
      const numbered = `${end + 1}: ${line}`;
      const t = estimateTokens(numbered) + 1;
      if (out.length > 0 && tokens + t > maxTokens) break;
      out.push(numbered);
      tokens += t;
      end++;
    }

    chunks.push({ startLine: start + 1, endLine: end, text: out.join('\n') });
    if (end >= lines.length) break;
    start = Math.max(end - overlap, start + 1);
  }
  return chunks;
}

// Used when Groq returns 413: split an already-numbered chunk in half
function splitChunk(chunk) {
  const lines = chunk.text.split('\n');
  if (lines.length < 2) return null;
  const mid = Math.floor(lines.length / 2);
  return [
    { startLine: chunk.startLine, text: lines.slice(0, mid).join('\n') },
    { startLine: chunk.startLine + mid, text: lines.slice(mid).join('\n') },
  ];
}

// ---------- Error description (shows the REAL cause of "fetch failed") ----------

function describeError(err) {
  const cause = err.cause
    ? ` (cause: ${err.cause.code || err.cause.message})`
    : '';
  const status = err.status ? `HTTP ${err.status}: ` : '';
  return `${status}${err.message}${cause}`;
}

// ---------- Retry with backoff ----------

const NON_RETRYABLE = [400, 401, 403, 404, 413];

async function withRetry(fn, { retries = 3, baseDelay = 2000 } = {}) {
  let lastErr;
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      const status = err.status || err.response?.status;

      // Retrying these will never help
      if (NON_RETRYABLE.includes(status)) throw err;
      if (attempt === retries) break;

      let wait;
      if (status === 429) {
        const ra = Number(err.retryAfter);
        wait = ra > 0 ? ra * 1000 + 500 : baseDelay * 2 ** attempt;
      } else {
        // 5xx or network failure ("fetch failed")
        wait = baseDelay * 2 ** (attempt - 1) + Math.random() * 500;
      }
      wait = Math.min(wait, 60000);

      console.log(
        `   ⏳ ${describeError(err)} — retry ${attempt}/${retries - 1} in ${Math.round(wait / 1000)}s`
      );
      await sleep(wait);
    }
  }
  throw lastErr;
}

// ---------- Circuit breaker ----------
// 3 failures in a row -> pause 30s. Fails again 3 in a row -> abort scan.
// Any success resets everything.

class CircuitBreaker {
  constructor({ threshold = 3, cooldownMs = 30000, maxPauses = 1 } = {}) {
    this.threshold = threshold;
    this.cooldownMs = cooldownMs;
    this.maxPauses = maxPauses;
    this.failures = 0;
    this.pauses = 0;
  }

  recordSuccess() {
    this.failures = 0;
    this.pauses = 0;
  }

  recordFailure() {
    this.failures++;
  }

  // Call before every request. Returns false => abort the scan.
  async beforeRequest() {
    if (this.failures < this.threshold) return true;

    this.pauses++;
    if (this.pauses > this.maxPauses) {
      console.log('🛑 Too many consecutive failures. Stopping scan (partial report will be saved).');
      return false;
    }
    console.log(
      `⚠️  ${this.failures} failures in a row. Pausing ${this.cooldownMs / 1000}s...`
    );
    await sleep(this.cooldownMs);
    this.failures = 0;
    return true;
  }
}

// ---------- Scan one file safely ----------
// Pattern findings are ALWAYS kept, even if the LLM layer fails.
// status: scanned | partial | failed | skipped

async function scanFileResilient({
  path,
  content,
  patternFindings = [],
  analyzeChunk,
  breaker,
  delayMs = 2000,
}) {
  const result = {
    path,
    status: 'scanned',
    findings: [...patternFindings],
    errors: [],
    aborted: false,
  };

  const allChunks = chunkFile(content);
  const chunks = allChunks.slice(0, MAX_CHUNKS_PER_FILE);
  const truncated = allChunks.length > MAX_CHUNKS_PER_FILE;

  let ok = 0;
  let failed = 0;

  // Analyze one chunk; on 413, split in half and try each half
  async function analyzeOne(chunk, depth = 0) {
    try {
      return await withRetry(() =>
        analyzeChunk(chunk.text, chunk.startLine, path)
      );
    } catch (err) {
      if (err.status === 413 && depth < 2) {
        const parts = splitChunk(chunk);
        if (parts) {
          console.log(`   ✂️  Chunk too big, splitting (lines from ${chunk.startLine})`);
          const found = [];
          for (const p of parts) found.push(...(await analyzeOne(p, depth + 1)));
          return found;
        }
      }
      throw err;
    }
  }

  for (const chunk of chunks) {
    const proceed = await breaker.beforeRequest();
    if (!proceed) {
      result.aborted = true;
      break;
    }

    try {
      const found = await analyzeOne(chunk);
      result.findings.push(...found);
      breaker.recordSuccess();
      ok++;
    } catch (err) {
      failed++;
      result.errors.push(describeError(err));
      // 413 = our content problem, not a service problem: don't trip the breaker
      if (err.status !== 413) breaker.recordFailure();
      console.log(`   ❌ ${describeError(err)}`);
    }

    await sleep(delayMs);
  }

  if (result.aborted && ok === 0) result.status = 'skipped';
  else if (ok === 0 && failed > 0) result.status = 'failed';
  else if (failed > 0 || truncated || result.aborted) result.status = 'partial';
  else result.status = 'scanned';

  if (truncated) result.errors.push(`File truncated: only first ${MAX_CHUNKS_PER_FILE} chunks scanned`);

  return result;
}

// ---------- Honest coverage report ----------

function printCoverage(results) {
  const by = (s) => results.filter((r) => r.status === s);
  const scanned = by('scanned');
  const partial = by('partial');
  const failed = by('failed');
  const skipped = by('skipped');

  console.log('\n📊 COVERAGE');
  console.log(`   ✅ Fully scanned: ${scanned.length}`);
  console.log(`   🟡 Partially scanned: ${partial.length}`);
  console.log(`   ❌ Failed (pattern layer only): ${failed.length}`);
  console.log(`   ⏭️  Skipped: ${skipped.length}`);

  const problem = [...partial, ...failed, ...skipped];
  if (problem.length) {
    console.log('\n   Files NOT fully analyzed:');
    for (const r of problem) {
      console.log(`   - ${r.path} [${r.status}]${r.errors[0] ? ' — ' + r.errors[0] : ''}`);
    }
    console.log('\n   ⚠️  "No findings" does NOT mean safe for these files.');
  }
}

// ---------- Scan the risky files first ----------

const HIGH_RISK = /(auth|login|session|password|token|jwt|route|controller|api|server|app\.|db|database|model|query|sql|config|upload|admin|payment)/i;
const LOW_VALUE = /(^|\/)(test|tests|__tests__|spec|e2e|docs?|examples?|fixtures?|mocks?|data\/static|codefixes)(\/|$)|\.(test|spec)\.|\.config\./i;

function priorityScore(path) {
  let s = 0;
  if (HIGH_RISK.test(path)) s += 2;
  if (LOW_VALUE.test(path)) s -= 3;
  return s;
}

// Works on strings or objects with a .path
function prioritizeFiles(files) {
  const p = (f) => (typeof f === 'string' ? f : f.path);
  return [...files].sort((a, b) => priorityScore(p(b)) - priorityScore(p(a)));
}

module.exports = {
  chunkFile,
  splitChunk,
  withRetry,
  describeError,
  CircuitBreaker,
  scanFileResilient,
  printCoverage,
  prioritizeFiles,
  estimateTokens,
  sleep,
};

