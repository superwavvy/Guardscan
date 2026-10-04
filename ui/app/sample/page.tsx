import { Shield, ArrowLeft, ExternalLink, AlertTriangle, ChevronDown } from "lucide-react";

const SAMPLE_SCAN = {
  repo_name: "expressjs/express",
  branch: "master",
  scan_time: "2026-10-04T11:32:14Z",
  scanned_files: 29,
  total_files: 141,
  partial_files: 1,
  failed_files: 1,
  skipped_files: 0,
  total_vulnerabilities: 15,
  high_count: 9,
  medium_count: 3,
  low_count: 3,
};

const SAMPLE_FINDINGS = [
  {
    id: "1",
    severity: "HIGH",
    type: "Path Traversal",
    cwe_id: "CWE-22",
    owasp_category: "A01:2025",
    file: "lib/response.js",
    line: 480,
    description: "The res.download implementation resolves a user-controlled 'path' with resolve(path) without validating that it stays within opts.root, allowing an attacker to request arbitrary files on the server filesystem.",
    code_snippet: "path = resolve(path);",
    fix: "Validate that the resolved path is within the configured root directory before serving. Use path.relative() and reject any result starting with '..'.",
    source: "llm",
    verified: true,
    occurrence_count: 1,
    occurrences: [],
  },
  {
    id: "2",
    severity: "HIGH",
    type: "Host Header Injection",
    cwe_id: "CWE-644",
    owasp_category: "A01:2025",
    file: "lib/request.js",
    line: 418,
    description: "The 'host' getter trusts the X-Forwarded-Host header when 'trust proxy' is enabled, which can be manipulated to control the perceived host and lead to open redirects, SSRF, or cache poisoning.",
    code_snippet: 'return this.get("X-Forwarded-Host") || undefined;',
    fix: "Only trust X-Forwarded-Host when explicitly configured with a known allowlist. Document the security implications of enabling trust proxy.",
    source: "llm",
    verified: true,
    occurrence_count: 1,
    occurrences: [],
  },
  {
    id: "3",
    severity: "HIGH",
    type: "Cross-Site Scripting (XSS)",
    cwe_id: "CWE-79",
    owasp_category: "A05:2025",
    file: "lib/response.js",
    line: 290,
    description: "The JSONP callback name is taken from a query parameter and only loosely sanitized with a regex, allowing crafted callback values that can execute arbitrary JavaScript when the response is interpreted.",
    code_snippet: "callback = callback.replace(/[^\\[\\]\\w$.]/g, '');",
    fix: "Validate the callback name against a strict allowlist of characters (alphanumeric, underscore, dot). Reject anything else with a 400 error.",
    source: "both",
    verified: true,
    occurrence_count: 1,
    occurrences: [],
  },
  {
    id: "4",
    severity: "MEDIUM",
    type: "Prototype Pollution",
    cwe_id: "CWE-1321",
    owasp_category: "A03:2025",
    file: "lib/application.js",
    line: 536,
    description: "Object spread merges 'opts._locals' into 'renderOptions' without sanitization. If an attacker supplies a property named '__proto__', it can modify the prototype of renderOptions.",
    code_snippet: "renderOptions = Object.assign({}, opts._locals, renderOptions);",
    fix: "Use a safe merge function that skips __proto__, constructor, and prototype keys. Consider Object.create(null) for the target object.",
    source: "llm",
    verified: true,
    occurrence_count: 1,
    occurrences: [],
  },
  {
    id: "5",
    severity: "LOW",
    type: "Insecure Transport",
    cwe_id: "CWE-319",
    owasp_category: "A04:2025",
    file: "lib/response.js",
    line: 85,
    description: "Plain HTTP URL detected in a response helper — data could be transmitted unencrypted if called from a non-HTTPS context.",
    code_snippet: '"http://expressjs.com/en/4x/api.html#res"',
    fix: "Use HTTPS URLs in documentation and code samples. This finding is likely informational for a library, but flagged for awareness.",
    source: "pattern",
    verified: false,
    occurrence_count: 10,
    occurrences: [
      { file: "lib/response.js", line: 85 },
      { file: "lib/response.js", line: 86 },
      { file: "lib/response.js", line: 88 },
      { file: "lib/response.js", line: 89 },
      { file: "lib/response.js", line: 788 },
    ],
  },
];

export default function SampleReport() {
  const severityColors: Record<string, string> = {
    HIGH: "text-red-400 border-red-500/30 bg-red-500/5",
    MEDIUM: "text-amber-400 border-amber-500/30 bg-amber-500/5",
    LOW: "text-[#5a616e] border-[#1a1c22] bg-[#0f1014]",
  };

  const s = SAMPLE_SCAN;

  return (
    <main className="min-h-screen">
      <header className="border-b border-[#1a1c22] sticky top-0 bg-[#0a0a0c]/95 backdrop-blur z-10">
        <div className="max-w-5xl mx-auto px-6 py-4 flex items-center gap-3">
          <a href="/" className="text-[#5a616e] hover:text-[#4a9ab5] transition-colors">
            <ArrowLeft className="w-3.5 h-3.5" />
          </a>
          <Shield className="w-3.5 h-3.5 text-[#4a9ab5]" />
          <span className="text-[11px] font-semibold tracking-wider text-[#c5c9d1]">GUARDSCAN</span>
          <span className="text-[10px] text-[#5a616e] ml-1">/ SAMPLE</span>
          <span className="ml-auto text-[10px] text-[#5a616e] border border-[#1a1c22] px-1.5 py-px">
            DEMO DATA
          </span>
        </div>
      </header>

      <div className="max-w-5xl mx-auto px-6 py-8">
        <div className="border border-[#4a9ab5]/20 bg-[#4a9ab5]/5 text-[11px] text-[#8ec7db] px-4 py-3 mb-8">
          This is a static sample report. Real scans show the same layout with findings from your actual repository.
        </div>

        <div className="mb-8">
          <div className="flex items-center gap-2 mb-2 text-[10px] text-[#5a616e]">
            <span>REPOSITORY</span>
            <a href="https://github.com/expressjs/express" target="_blank" rel="noopener noreferrer" className="text-[#4a9ab5] hover:underline flex items-center gap-1">
              {s.repo_name} <ExternalLink className="w-2.5 h-2.5" />
            </a>
          </div>
          <h1 className="text-lg font-medium text-[#c5c9d1] mb-1">Security Report</h1>
          <p className="text-[10px] text-[#5a616e]">
            Scanned {new Date(s.scan_time).toLocaleString()} · {s.scanned_files}/{s.total_files} files · {s.total_vulnerabilities} findings
          </p>
        </div>

        <div className="grid grid-cols-4 gap-3 mb-8">
          <StatBox label="TOTAL" value={s.total_vulnerabilities} />
          <StatBox label="HIGH" value={s.high_count} color="text-red-400" />
          <StatBox label="MEDIUM" value={s.medium_count} color="text-amber-400" />
          <StatBox label="LOW" value={s.low_count} color="text-[#5a616e]" />
        </div>

        <div className="border border-[#1a1c22] bg-[#0f1014] p-4 mb-4 text-[11px]">
          <div className="text-[#5a616e] tracking-widest mb-2 text-[10px]">COVERAGE</div>
          <div className="flex flex-wrap gap-4">
            <span className="text-emerald-400">✓ {s.scanned_files} scanned</span>
            {s.partial_files > 0 && <span className="text-amber-400">● {s.partial_files} partial</span>}
            {s.failed_files > 0 && <span className="text-red-400">✗ {s.failed_files} failed</span>}
          </div>
          <div className="mt-3 text-[10px] text-[#5a616e] flex items-start gap-2">
            <AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" />
            <span>&quot;No findings&quot; does not mean safe for partial or failed files.</span>
          </div>
        </div>

        {/* Legend */}
        <details className="mb-4 border border-[#1a1c22] bg-[#0f1014] group">
          <summary className="cursor-pointer list-none p-3 text-[10px] text-[#5a616e] tracking-widest flex items-center justify-between hover:text-[#c5c9d1] transition-colors">
            <span>NOTE</span>
            <ChevronDown className="w-3 h-3 transition-transform group-open:rotate-180" />
          </summary>
          <div className="border-t border-[#1a1c22] p-3 text-[10px] text-[#5a616e] space-y-2">
            <div className="flex items-start gap-2">
              <span className="text-[#4a9ab5] shrink-0 w-16">PATTERN</span>
              <span>Finding surfaced by deterministic regex rules (100% reproducible)</span>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-[#4a9ab5] shrink-0 w-16">LLM</span>
              <span>Finding surfaced by AI analysis (contextual, may vary between runs)</span>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-emerald-400 shrink-0 w-16">VERIFIED</span>
              <span>LLM finding whose claimed line and snippet matched the actual file</span>
            </div>
            <div className="flex items-start gap-2">
              <span className="text-[#4a9ab5] shrink-0 w-16">CORROB.</span>
              <span>Both pattern and LLM layers flagged the same issue independently</span>
            </div>
          </div>
        </details>

        <div className="space-y-2">
          {SAMPLE_FINDINGS.map((f) => (
            <details
              key={f.id}
              className="border border-[#1a1c22] bg-[#0f1014] group"
              open={f.id === "1"}
            >
              <summary className="cursor-pointer list-none p-4 flex items-start gap-3 hover:bg-[#131419] transition-colors">
                <span className={`text-[9px] px-1.5 py-0.5 border shrink-0 font-semibold tracking-wider ${severityColors[f.severity]}`}>
                  {f.severity}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className="text-[12px] text-[#c5c9d1]">{f.type}</span>
                    <span className="text-[9px] text-[#5a616e] border border-[#1a1c22] px-1.5 py-px">
                      {f.cwe_id}
                    </span>
                    {f.source === "both" && (
                      <span className="text-[9px] text-[#4a9ab5] border border-[#4a9ab5]/30 px-1.5 py-px">
                        CORROBORATED
                      </span>
                    )}
                  </div>
                  <div className="text-[10px] text-[#5a616e] truncate">
                    {f.file}:{f.line}
                    {f.occurrence_count > 1 && ` · seen in ${f.occurrence_count} files`}
                  </div>
                </div>
                <ChevronDown className="w-3.5 h-3.5 text-[#5a616e] shrink-0 transition-transform group-open:rotate-180" />
              </summary>

              <div className="border-t border-[#1a1c22] p-4 space-y-3">
                <div>
                  <div className="text-[9px] text-[#5a616e] tracking-widest mb-1.5">DESCRIPTION</div>
                  <div className="text-[12px] text-[#c5c9d1] leading-relaxed">{f.description}</div>
                </div>
                {f.code_snippet && (
                  <div>
                    <div className="text-[9px] text-[#5a616e] tracking-widest mb-1.5">CODE</div>
                    <pre className="bg-[#0a0a0c] border border-[#1a1c22] p-3 text-[11px] overflow-x-auto text-[#c5c9d1]">
                      <code>{f.code_snippet}</code>
                    </pre>
                  </div>
                )}
                <div>
                  <div className="text-[9px] text-[#5a616e] tracking-widest mb-1.5">FIX</div>
                  <div className="text-[12px] text-[#c5c9d1] leading-relaxed">{f.fix}</div>
                </div>
                {f.occurrences.length > 1 && (
                  <div>
                    <div className="text-[9px] text-[#5a616e] tracking-widest mb-1.5">
                      OCCURRENCES ({f.occurrences.length})
                    </div>
                    <ul className="text-[10px] text-[#5a616e] space-y-1">
                      {f.occurrences.slice(0, 5).map((o, i) => (
                        <li key={i}>· {o.file}:{o.line}</li>
                      ))}
                      {f.occurrences.length > 5 && <li>· and {f.occurrences.length - 5} more</li>}
                    </ul>
                  </div>
                )}
                <div className="flex items-center gap-3 text-[9px] text-[#5a616e] pt-2 border-t border-[#1a1c22] tracking-wider flex-wrap">
                  <span>SOURCE: {f.source.toUpperCase()}</span>
                  {f.verified && <span className="text-emerald-400">✓ VERIFIED</span>}
                  <span>{f.owasp_category}</span>
                </div>
              </div>
            </details>
          ))}
        </div>

        <div className="mt-12 border border-[#1a1c22] bg-[#0f1014] p-6 text-center">
          <div className="text-[12px] text-[#c5c9d1] mb-2">Run this against your own repo</div>
          <div className="text-[10px] text-[#5a616e] mb-4">Free. No signup. 30 seconds.</div>
          <a href="/" className="inline-block bg-[#4a9ab5] text-[#0a0a0c] px-5 py-2.5 text-[11px] font-semibold tracking-wider hover:bg-[#5aabca] transition-colors">
            SCAN A REPO →
          </a>
        </div>
      </div>
    </main>
  );
}

function StatBox({ label, value, color = "text-[#c5c9d1]" }: { label: string; value: number; color?: string }) {
  return (
    <div className="border border-[#1a1c22] bg-[#0f1014] p-3">
      <div className="text-[9px] text-[#5a616e] tracking-widest mb-1">{label}</div>
      <div className={`text-lg font-medium ${color}`}>{value}</div>
    </div>
  );
}
