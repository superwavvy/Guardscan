import { createClient } from "@supabase/supabase-js";

export const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
);

export type Scan = {
  id: string;
  repo_url: string;
  repo_name: string;
  branch: string | null;
  status: string;
  total_files: number;
  scanned_files: number;
  partial_files: number;
  failed_files: number;
  skipped_files: number;
  total_vulnerabilities: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  pattern_count: number;
  llm_count: number;
  both_count: number;
  scan_time: string;
  created_at: string;
};

export type Finding = {
  id: string;
  scan_id: string;
  file: string;
  line: number;
  type: string;
  severity: "HIGH" | "MEDIUM" | "LOW";
  confidence: string | null;
  owasp_category: string | null;
  cwe_id: string | null;
  description: string;
  code_snippet: string | null;
  fix: string;
  source: string | null;
  verified: boolean;
  occurrence_count: number;
  occurrences: { file: string; line: number }[];
};
