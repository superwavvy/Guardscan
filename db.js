const { createClient } = require('@supabase/supabase-js');

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY
);

// Save a full scan report to Supabase
async function saveScanReport(report) {
    console.log("\n💾 Saving report to Supabase...");

    // 1. Insert the scan row
    const { data: scanRow, error: scanError } = await supabase
        .from('scans')
        .insert({
            repo_url: report.repoUrl || `https://github.com/${report.repo}`,
            repo_name: report.repo,
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

    // 2. Insert the findings
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

module.exports = { supabase, saveScanReport };
