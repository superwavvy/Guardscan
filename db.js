const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);

// Check if we already have a scan for this repo + commit
async function findCachedScan(repoName, commitSha) {
    const { data, error } = await supabase
        .from('scans')
        .select('id, repo_name, commit_sha, total_vulnerabilities, high_count, medium_count, low_count, scan_time, created_at')
        .eq('repo_name', repoName)
        .eq('commit_sha', commitSha)
        .order('created_at', { ascending: false })
        .limit(1);

    if (error || !data || data.length === 0) return null;
    return data[0];
}

async function saveScanReport(report) {
    console.log("\n💾 Saving report to Supabase...");

    const { data: scanRow, error: scanError } = await supabase
        .from('scans')
        .insert({
            repo_url: report.repoUrl || `https://github.com/${report.repo}`,
            repo_name: report.repo,
            commit_sha: report.commitSha || null,
            branch: report.branch,
            status: 'complete',
            total_files: report.totalFiles,
            scanned_files: report.coverage.scanned,
            partial_files: report.coverage.partial,
            failed_files: report.coverage.failed,
            skipped_files: report.coverage.skipped,
            total_vulnerabilities: report.rawFindings,
            high_count: report.bySeverity.HIGH,
            medium_count: report.bySeverity.MEDIUM,
            low_count: report.bySeverity.LOW,
            pattern_count: report.bySource.pattern,
            llm_count: report.bySource.llm,
            both_count: report.bySource.both
        })
        .select()
        .single();

    if (scanError) {
        console.error("❌ Failed to save scan:", scanError.message);
        return null;
    }

    console.log(`   ✅ Scan saved: ${scanRow.id}`);

    if (report.findings.length > 0) {
        const findingRows = report.findings.map(f => ({
            scan_id: scanRow.id,
            file: f.file,
            line: f.line,
            type: f.type,
            severity: f.severity,
            confidence: f.confidence || null,
            owasp_category: f.owasp_category || null,
            cwe_id: f.cwe_id || null,
            description: f.description,
            code_snippet: f.code_snippet || null,
            fix: f.fix,
            source: f.source || null,
            verified: f.verified || false,
            occurrence_count: f.count || 1,
            occurrences: f.occurrences || []
        }));

        const { error: findingsError } = await supabase
            .from('findings')
            .insert(findingRows);

        if (findingsError) {
            console.error("❌ Failed to save findings:", findingsError.message);
        } else {
            console.log(`   ✅ Saved ${findingRows.length} findings`);
        }
    }

    return scanRow.id;
}

module.exports = { supabase, saveScanReport, findCachedScan };
