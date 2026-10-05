const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);

// Cache lookup — only complete scans
async function findCachedScan(repoName, commitSha) {
    const { data, error } = await supabase
        .from('scans')
        .select('id, repo_name, commit_sha, total_vulnerabilities, high_count, medium_count, low_count, scan_time, created_at')
        .eq('repo_name', repoName)
        .eq('commit_sha', commitSha)
        .eq('status', 'complete')
        .order('created_at', { ascending: false })
        .limit(1);

    if (error || !data || data.length === 0) return null;
    return data[0];
}

// Create a "scanning" placeholder row
async function createPendingScan(repoName, commitSha, branch) {
    const { data, error } = await supabase
        .from('scans')
        .insert({
            repo_url: `https://github.com/${repoName}`,
            repo_name: repoName,
            commit_sha: commitSha,
            branch,
            status: 'scanning'
        })
        .select()
        .single();

    if (error) {
        console.error("❌ Failed to create pending scan:", error.message);
        return null;
    }
    return data.id;
}

// Update the placeholder with final results + save findings
async function finalizeScan(scanId, report) {
    console.log(`\n💾 Finalizing scan ${scanId}...`);

    const planned = report.coverage.scanned + report.coverage.partial +
                    report.coverage.failed + report.coverage.skipped;
    const cacheable = planned > 0 && (report.coverage.scanned / planned) >= 0.8;

    const { error: updateError } = await supabase
        .from('scans')
        .update({
            status: 'complete',
            commit_sha: cacheable ? (report.commitSha || null) : null,
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
            both_count: report.bySource.both,
            scan_time: new Date().toISOString()
        })
        .eq('id', scanId);

    if (updateError) {
        console.error("❌ Failed to update scan:", updateError.message);
        return null;
    }

    if (report.findings.length > 0) {
        const findingRows = report.findings.map(f => ({
            scan_id: scanId,
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

        const { error: findingsError } = await supabase.from('findings').insert(findingRows);
        if (findingsError) console.error("❌ Failed to save findings:", findingsError.message);
        else console.log(`   ✅ Saved ${findingRows.length} findings`);
    }

    return scanId;
}

module.exports = { supabase, findCachedScan, createPendingScan, finalizeScan };
