"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { Shield, ArrowRight, Loader2, ChevronDown, Clock, Radio } from "lucide-react";
import { supabase } from "@/lib/supabase";

type RecentScan = {
  id: string;
  repo_name: string;
  status: string;
  total_vulnerabilities: number;
  high_count: number;
  scan_time: string;
  created_at: string;
};

export default function Home() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [recent, setRecent] = useState<RecentScan[]>([]);
  const router = useRouter();

  async function loadRecent() {
    const { data } = await supabase
      .from("scans")
      .select("id, repo_name, status, total_vulnerabilities, high_count, scan_time, created_at")
      .order("created_at", { ascending: false })
      .limit(30);

    if (!data) return;

    const seen = new Set<string>();
    const unique: RecentScan[] = [];
    for (const row of data) {
      if (seen.has(row.repo_name)) continue;
      seen.add(row.repo_name);
      unique.push(row);
      if (unique.length >= 6) break;
    }
    setRecent(unique);
  }

  useEffect(() => {
    loadRecent();
    const interval = setInterval(loadRecent, 5000);
    return () => clearInterval(interval);
  }, []);

  async function handleScan() {
    if (!url.trim()) return;
    setLoading(true);
    setError(null);

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repoUrl: url.trim() }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Scan failed");

      if (data.scanId) { router.push(`/scan/${data.scanId}`); } else { router.push(`/scanning?repo=${encodeURIComponent(url.trim())}`); }
    } catch (e: any) {
      setError(e.message);
      setLoading(false);
    }
  }

  function timeAgo(iso: string) {
    const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
    if (seconds < 60) return `${seconds}s ago`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    return `${Math.floor(hours / 24)}d ago`;
  }

  return (
    <main className="min-h-[100dvh] flex flex-col">
      <header className="border-b border-[#1a1c22]">
        <div className="max-w-5xl mx-auto px-6 py-4 flex items-center gap-3">
          <Shield className="w-3.5 h-3.5 text-[#4a9ab5]" />
          <span className="text-[11px] font-semibold tracking-wider text-[#c5c9d1]">GUARDSCAN</span>
          <span className="text-[10px] text-[#5a616e] border border-[#1a1c22] px-1.5 py-px">v1.0</span>
          <a href="/sample" className="ml-auto text-[10px] text-[#5a616e] hover:text-[#4a9ab5] tracking-widest transition-colors">
            SAMPLE REPORT →
          </a>
        </div>
      </header>

      <div className="flex-1 flex items-start justify-center px-6 pt-6 pb-4">
        <div className="w-full max-w-2xl">
          <div className="flex items-center gap-2 mb-6 text-[11px] text-[#5a616e]">
            <span className="text-[#4a9ab5]">&gt;</span>
            <span>Initializing security scanner</span>
            <span className="inline-block w-1.5 h-3 bg-[#4a9ab5] cursor" />
          </div>

          <h1 className="text-xl font-medium text-[#c5c9d1] leading-relaxed mb-3">
            Scan any GitHub repo for <span className="text-[#4a9ab5]">OWASP Top 10</span> vulnerabilities.
          </h1>

          <p className="text-[11px] text-[#5a616e] leading-relaxed mb-8">
            Two detection layers · Structured findings mapped to CWE and OWASP categories · Free, no signup
          </p>

          <div className="border border-[#1a1c22] bg-[#0f1014] focus-within:border-[#4a9ab5]/50 transition-colors">
            <div className="flex items-stretch">
              <span className="pl-4 pr-2 py-3 text-[#4a9ab5] text-[13px] select-none">&gt;</span>
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleScan()}
                placeholder="https://github.com/owner/repo"
                disabled={loading}
                className="flex-1 bg-transparent py-3 pr-3 text-[13px] outline-none placeholder:text-[#3d434e] text-[#c5c9d1]"
              />
              <button
                onClick={handleScan}
                disabled={loading || !url.trim()}
                className="bg-[#4a9ab5] text-[#0a0a0c] px-5 text-[11px] font-semibold tracking-wider hover:bg-[#5aabca] disabled:opacity-25 disabled:cursor-not-allowed flex items-center gap-1.5 transition-colors"
              >
                {loading ? (<><Loader2 className="w-3 h-3 animate-spin" />SCANNING</>) : (<>SCAN<ArrowRight className="w-3 h-3" /></>)}
              </button>
            </div>
          </div>

          <div className="mt-2 text-[10px] text-[#3d434e] flex flex-wrap gap-x-3 gap-y-1">
            <span>Try:</span>
            <button onClick={() => setUrl("https://github.com/expressjs/express")} className="hover:text-[#4a9ab5] transition-colors">expressjs/express</button>
            <button onClick={() => setUrl("https://github.com/axios/axios")} className="hover:text-[#4a9ab5] transition-colors">axios/axios</button>
            <button onClick={() => setUrl("https://github.com/superwavvy/guardpr-test")} className="hover:text-[#4a9ab5] transition-colors">superwavvy/guardpr-test</button>
          </div>

          {error && (
            <div className="mt-3 border border-red-500/20 bg-red-500/5 text-red-400 text-[11px] px-3 py-2.5">✗ {error}</div>
          )}

          {recent.length > 0 && (
            <div className="mt-10 border-t border-[#1a1c22] pt-6">
              <div className="text-[10px] text-[#5a616e] tracking-widest mb-3 flex items-center gap-2">
                <Clock className="w-3 h-3" />RECENTLY SCANNED
              </div>
              <div className="space-y-1">
                {recent.map((scan) => {
                  const isScanning = scan.status === "scanning";
                  return (
                    <button
                      key={scan.id}
                      disabled={isScanning}
                      onClick={() => !isScanning && router.push(`/scan/${scan.id}`)}
                      className={`w-full text-left flex items-center gap-3 py-2 px-3 border border-transparent transition-colors group ${
                        isScanning ? "cursor-wait" : "hover:bg-[#0f1014] hover:border-[#1a1c22]"
                      }`}
                    >
                      {isScanning && <Radio className="w-3 h-3 text-[#4a9ab5] animate-pulse shrink-0" />}
                      <span className={`text-[12px] truncate flex-1 ${isScanning ? "text-[#5a616e]" : "text-[#c5c9d1] group-hover:text-[#4a9ab5]"} transition-colors`}>
                        {scan.repo_name}
                      </span>
                      {isScanning ? (
                        <span className="text-[10px] text-[#4a9ab5] shrink-0">SCANNING</span>
                      ) : (
                        <span className="text-[10px] text-[#5a616e] shrink-0">{timeAgo(scan.created_at)}</span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          <div className="mt-10 border-t border-[#1a1c22] pt-6 grid grid-cols-1 md:grid-cols-3 gap-6 text-[11px]">
            <details className="group">
              <summary className="cursor-pointer list-none">
                <div className="text-[#5a616e] tracking-widest mb-1.5 flex items-center gap-1.5">
                  DETECTION LAYERS<ChevronDown className="w-3 h-3 transition-transform group-open:rotate-180" />
                </div>
                <div className="text-[#c5c9d1] text-base">2</div>
              </summary>
              <div className="mt-3 text-[10px] text-[#5a616e] leading-relaxed space-y-1.5">
                <div><span className="text-[#4a9ab5]">· Pattern</span> — deterministic regex rules</div>
                <div><span className="text-[#4a9ab5]">· LLM</span> — contextual analysis mapped to OWASP Top 10:2025</div>
              </div>
            </details>
            <div>
              <div className="text-[#5a616e] tracking-widest mb-1.5">MAX FILES / SCAN</div>
              <div className="text-[#c5c9d1] text-base">20</div>
              <div className="mt-1.5 text-[10px] text-[#5a616e]">Priority files first — auth, routes, config, DB</div>
            </div>
            <div>
              <div className="text-[#5a616e] tracking-widest mb-1.5">AVG SCAN TIME</div>
              <div className="text-[#c5c9d1] text-base">1-7 min</div>
              <div className="mt-1.5 text-[10px] text-[#5a616e]">Cached scans return instantly</div>
            </div>
          </div>
        </div>
      </div>

      <footer className="border-t border-[#1a1c22] px-6 py-5">
        <div className="max-w-5xl mx-auto text-[10px] text-[#5a616e] tracking-widest">
          GUARDSCAN IS A FIRST-PASS TRIAGE TOOL · NOT A REPLACEMENT FOR A PROFESSIONAL SECURITY AUDIT
        </div>
      </footer>
    </main>
  );
}
