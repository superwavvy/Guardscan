"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { supabase, type Scan, type Finding } from "@/lib/supabase";
import { Shield, ArrowLeft, Loader2, ExternalLink, AlertTriangle, ChevronDown, Info } from "lucide-react";

export default function ScanReport() {
  const params = useParams();
  const router = useRouter();
  const scanId = params.id as string;

  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<"ALL" | "HIGH" | "MEDIUM" | "LOW">("ALL");

  useEffect(() => {
    async function load() {
      const { data: scanData } = await supabase
        .from("scans")
        .select("*")
        .eq("id", scanId)
        .single();

      const { data: findingsData } = await supabase
        .from("findings")
        .select("*")
        .eq("scan_id", scanId);

      setScan(scanData as Scan);
      setFindings((findingsData as Finding[]) || []);
      setLoading(false);
    }
    load();
  }, [scanId]);

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="w-4 h-4 animate-spin text-[#4a9ab5]" />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="min-h-screen flex items-center justify-center text-[11px] text-[#5a616e]">
        Scan not found.
      </div>
    );
  }

  const severityColors: Record<string, string> = {
    HIGH: "text-red-400 border-red-500/30 bg-red-500/5",
    MEDIUM: "text-amber-400 border-amber-500/30 bg-amber-500/5",
    LOW: "text-[#5a616e] border-[#1a1c22] bg-[#0f1014]",
  };

  const severityOrder: Record<string, number> = { HIGH: 0, MEDIUM: 1, LOW: 2 };
  const sorted = [...findings].sort(
    (a, b) => (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3)
  );
  const filtered = filter === "ALL" ? sorted : sorted.filter((f) => f.severity === filter);

  const repoUrl = `https://github.com/${scan.repo_name}`;

  return (
    <main className="min-h-screen">
      <header className="border-b border-[#1a1c22] sticky top-0 bg-[#0a0a0c]/95 backdrop-blur z-10">
        <div className="max-w-5xl mx-auto px-6 py-4 flex items-center gap-3">
          <button onClick={() => router.push("/")} className="text-[#5a616e] hover:text-[#4a9ab5] transition-colors">
            <ArrowLeft className="w-3.5 h-3.5" />
          </button>
          <Shield className="w-3.5 h-3.5 text-[#4a9ab5]" />
          <span className="text-[11px] font-semibold tracking-wider text-[#c5c9d1]">GUARDSCAN</span>
          <span className="text-[10px] text-[#5a616e] ml-1 truncate max-w-[180px]">/ {scan.repo_name}</span>
        </div>
      </header>

      <div className="max-w-5xl mx-auto px-6 py-8">
        {/* Repo header */}
        <div className="mb-8">
          <div className="flex items-center gap-2 mb-2 text-[10px] text-[#5a616e]">
            <span>REPOSITORY</span>
            <a href={repoUrl} target="_blank" rel="noopener noreferrer" className="text-[#4a9ab5] hover:underline flex items-center gap-1">
              {scan.repo_name} <ExternalLink className="w-2.5 h-2.5" />
            </a>
          </div>
          <h1 className="text-lg font-medium text-[#c5c9d1] mb-1">Security Report</h1>
          <p className="text-[10px] text-[#5a616e]">
            Scanned {new Date(scan.scan_time).toLocaleString()} · {scan.scanned_files}/{scan.total_files} files · {scan.total_vulnerabilities} findings
          </p>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-4 gap-3 mb-8">
          <StatBox label="TOTAL" value={scan.total_vulnerabilities} />
          <StatBox label="HIGH" value={scan.high_count} color="text-red-400" />
          <StatBox label="MEDIUM" value={scan.medium_count} color="text-amber-400" />
          <StatBox label="LOW" value={scan.low_count} color="text-[#5a616e]" />
        </div>

        {/* Coverage */}
        <div className="border border-[#1a1c22] bg-[#0f1014] p-4 mb-4 text-[11px]">
          <div className="text-[#5a616e] tracking-widest mb-2 text-[10px]">COVERAGE</div>
          <div className="flex flex-wrap gap-4">
            <span className="text-emerald-400">✓ {scan.scanned_files} scanned</span>
            {scan.partial_files > 0 && <span className="text-amber-400">● {scan.partial_files} partial</span>}
            {scan.failed_files > 0 && <span className="text-red-400">✗ {scan.failed_files} failed</span>}
            {scan.skipped_files > 0 && <span className="text-[#5a616e]">⏭ {scan.skipped_files} skipped</span>}
          </div>
          {(scan.partial_files > 0 || scan.failed_files > 0) && (
            <div className="mt-3 text-[10px] text-[#5a616e] flex items-start gap-2">
              <AlertTriangle className="w-3 h-3 mt-0.5 shrink-0" />
              <span>&quot;No findings&quot; does not mean safe for partial or failed files.</span>
            </div>
          )}
        </div>

        {/* Best-effort disclaimer */}
        <div className="border border-[#1a1c22] bg-[#0f1014] p-4 mb-8 text-[10px] text-[#5a616e] flex items-start gap-2">
          <Info className="w-3 h-3 mt-0.5 shrink-0" />
          <span>
            Findings are best-effort. False positives and false negatives are possible.
            Always verify before fixing.
          </span>
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

        {/* Filter tabs */}
        <div className="flex gap-1.5 mb-4">
          {(["ALL", "HIGH", "MEDIUM", "LOW"] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1.5 text-[10px] tracking-widest border transition-colors ${
                filter === f
                  ? "border-[#4a9ab5] text-[#4a9ab5] bg-[#4a9ab5]/5"
                  : "border-[#1a1c22] text-[#5a616e] hover:text-[#c5c9d1]"
              }`}
            >
              {f}
            </button>
          ))}
        </div>

        {/* Findings */}
        <div className="space-y-2">
          {filtered.length === 0 && (
            <div className="border border-[#1a1c22] bg-[#0f1014] p-8 text-center text-[11px] text-[#5a616e]">
              No findings in this category.
            </div>
          )}

          {filtered.map((f) => (
            <details key={f.id} className="border border-[#1a1c22] bg-[#0f1014] group">
              <summary className="cursor-pointer list-none p-4 flex items-start gap-3 hover:bg-[#131419] transition-colors">
                <span className={`text-[9px] px-1.5 py-0.5 border shrink-0 font-semibold tracking-wider ${severityColors[f.severity]}`}>
                  {f.severity}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <span className="text-[12px] text-[#c5c9d1]">{f.type}</span>
                    {f.cwe_id && (
                      <span className="text-[9px] text-[#5a616e] border border-[#1a1c22] px-1.5 py-px">
                        {f.cwe_id}
                      </span>
                    )}
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

                {f.occurrences && f.occurrences.length > 1 && (
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
                  <span>SOURCE: {(f.source || "unknown").toUpperCase()}</span>
                  {f.verified && <span className="text-emerald-400">✓ VERIFIED</span>}
                  {f.owasp_category && <span>{f.owasp_category}</span>}
                </div>
              </div>
            </details>
          ))}
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
