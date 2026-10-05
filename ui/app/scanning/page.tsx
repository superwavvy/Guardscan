"use client";

import { useEffect, useState, Suspense } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { supabase } from "@/lib/supabase";
import { Shield, Loader2 } from "lucide-react";

function ScanningContent() {
  const params = useSearchParams();
  const router = useRouter();
  const repoName = params.get("repo") || "";
  const [elapsed, setElapsed] = useState(0);

  useEffect(() => {
    if (!repoName) return;

    // Extract owner/repo from URL
    const clean = repoName.replace(/^(https?:\/\/)?(www\.)?github\.com\//, "").replace(/\/$/, "");

    const startTime = Date.now();

    const tick = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startTime) / 1000));
    }, 1000);

    const poll = setInterval(async () => {
      const { data } = await supabase
        .from("scans")
        .select("id")
        .eq("repo_name", clean)
        .gte("created_at", new Date(startTime - 10000).toISOString())
        .order("created_at", { ascending: false })
        .limit(1);

      if (data && data.length > 0) {
        clearInterval(poll);
        clearInterval(tick);
        router.push(`/scan/${data[0].id}`);
      }
    }, 3000);

    return () => {
      clearInterval(poll);
      clearInterval(tick);
    };
  }, [repoName, router]);

  return (
    <main className="min-h-[100dvh] flex flex-col">
      <header className="border-b border-[#1a1c22]">
        <div className="max-w-5xl mx-auto px-6 py-4 flex items-center gap-3">
          <Shield className="w-3.5 h-3.5 text-[#4a9ab5]" />
          <span className="text-[11px] font-semibold tracking-wider text-[#c5c9d1]">GUARDSCAN</span>
          <span className="text-[10px] text-[#5a616e] ml-1">/ SCANNING</span>
        </div>
      </header>

      <div className="flex-1 flex items-center justify-center px-6">
        <div className="w-full max-w-md">
          <div className="flex items-center gap-3 mb-6">
            <Loader2 className="w-4 h-4 animate-spin text-[#4a9ab5]" />
            <span className="text-[13px] text-[#c5c9d1]">Scanning repository...</span>
          </div>

          <div className="border border-[#1a1c22] bg-[#0f1014] p-5 text-[11px] space-y-3">
            <div className="flex justify-between">
              <span className="text-[#5a616e]">Repo</span>
              <span className="text-[#c5c9d1] truncate ml-4">{repoName}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#5a616e]">Elapsed</span>
              <span className="text-[#c5c9d1]">{elapsed}s</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#5a616e]">Expected</span>
              <span className="text-[#c5c9d1]">1-7 min</span>
            </div>
          </div>

          <p className="text-[10px] text-[#5a616e] mt-6 leading-relaxed">
            Results save to your scan history automatically. This page will
            redirect when the scan completes. You can close this tab and come
            back later — the scan continues on our server.
          </p>
        </div>
      </div>
    </main>
  );
}

export default function ScanningPage() {
  return (
    <Suspense fallback={<div className="min-h-screen flex items-center justify-center"><Loader2 className="w-5 h-5 animate-spin text-[#4a9ab5]" /></div>}>
      <ScanningContent />
    </Suspense>
  );
}
