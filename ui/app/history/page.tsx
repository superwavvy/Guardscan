"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { supabase, type Scan } from "@/lib/supabase";
import { Shield, ArrowLeft, Loader2 } from "lucide-react";

export default function History() {
  const router = useRouter();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      const { data } = await supabase
        .from("scans")
        .select("*")
        .order("created_at", { ascending: false })
        .limit(50);
      setScans((data as Scan[]) || []);
      setLoading(false);
    }
    load();
  }, []);

  return (
    <main className="min-h-screen scanlines">
      <header className="border-b border-[#1e2128]">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center gap-3">
          <button onClick={() => router.push("/")} className="text-[#6b7280] hover:text-[#00d9ff]">
            <ArrowLeft className="w-4 h-4" />
          </button>
          <Shield className="w-4 h-4 text-[#00d9ff]" />
          <span className="text-sm font-semibold tracking-tight">GUARDSCAN</span>
          <span className="text-xs text-[#6b7280] ml-2">/ HISTORY</span>
        </div>
      </header>

      <div className="max-w-6xl mx-auto px-6 py-8">
        <h1 className="text-3xl font-bold tracking-tight mb-6">Scan History</h1>

        {loading ? (
          <div className="flex justify-center py-20">
            <Loader2 className="w-6 h-6 animate-spin text-[#00d9ff]" />
          </div>
        ) : scans.length === 0 ? (
          <div className="border border-[#1e2128] bg-[#12141a] p-8 text-center text-sm text-[#6b7280]">
            No scans yet. Run your first scan from the home page.
          </div>
        ) : (
          <div className="border border-[#1e2128] divide-y divide-[#1e2128]">
            {scans.map((s) => (
              <button
                key={s.id}
                onClick={() => router.push(`/scan/${s.id}`)}
                className="w-full text-left p-4 hover:bg-[#161821] transition-colors flex items-center gap-4"
              >
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium mb-1">{s.repo_name}</div>
                  <div className="text-xs text-[#6b7280]">
                    {new Date(s.scan_time).toLocaleString()} ·{" "}
                    {s.scanned_files}/{s.total_files} files
                  </div>
                </div>
                <div className="flex items-center gap-3 text-xs shrink-0">
                  {s.high_count > 0 && (
                    <span className="text-red-400">{s.high_count} HIGH</span>
                  )}
                  {s.medium_count > 0 && (
                    <span className="text-amber-400">{s.medium_count} MED</span>
                  )}
                  {s.low_count > 0 && (
                    <span className="text-[#6b7280]">{s.low_count} LOW</span>
                  )}
                </div>
              </button>
            ))}
          </div>
        )}
      </div>
    </main>
  );
}
