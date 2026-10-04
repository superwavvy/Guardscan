require('dotenv').config();
const { saveScanReport } = require('./db.js');
const fs = require('fs');
const { parseGitHubUrl, getRepoTree, getAllFileContents } = require('./fetcher.js');
const { analyzeChunk } = require('./analyzer.js');
const { scanWithPatterns } = require('./patterns.js');
const P = require('./guardscan-patch.js');
const R = require('./resilience.js');

const MAX_FILES = 30;

// --- Normalize type strings for dedupe ---
function normalizeType(type) {
    return type
        .toLowerCase()
        .replace(/[^\w\s]/g, '')
        .replace(/s\b/g, '')
        .replace(/\s+/g, ' ')
        .trim();
}

// --- Merge pattern + LLM findings (corroboration) ---
function mergeFindings(findings) {
    const map = new Map();

    // Patterns first
    for (const f of findings) {
        if (f.source !== "pattern") continue;
        const key = `${f.file}::${f.line}::${normalizeType(f.type)}`;
        map.set(key, f);
    }

    // LLM findings: merge if they match a pattern
    for (const f of findings) {
        if (f.source === "pattern") continue;
        const key = `${f.file}::${f.line}::${normalizeType(f.type)}`;
        if (!map.has(key)) {
            map.set(key, f);
        } else {
            const existing = map.get(key);
            existing.source = "both";
            existing.corroborated = true;
        }
    }

    return Array.from(map.values());
}

// --- Final aggregate + sort ---
function aggregateFindings(findings) {
    const seen = new Set();
    const unique = [];

    for (const f of findings) {
        const key = `${f.file}::${f.line}::${normalizeType(f.type)}`;
        if (seen.has(key)) continue;
        seen.add(key);
        unique.push(f);
    }

    const severityOrder = { HIGH: 0, MEDIUM: 1, LOW: 2 };
    unique.sort((a, b) => {
        const sevDiff = (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3);
        if (sevDiff !== 0) return sevDiff;
        if (a.file !== b.file) return a.file.localeCompare(b.file);
        return a.line - b.line;
    });

    return unique;
}

// --- Group findings with the same CWE + type ---
function groupFindings(findings) {
    const groups = new Map();

    for (const f of findings) {
        const descKey = (f.description || "").slice(0, 60);
        const key = `${f.cwe_id}::${normalizeType(f.type)}::${descKey}`;

        if (!groups.has(key)) {
            groups.set(key, {
                ...f,
                occurrences: [{ file: f.file, line: f.line, code_snippet: f.code_snippet || "" }],
                count: 1
            });
        } else {
            const g = groups.get(key);
            g.occurrences.push({ file: f.file, line: f.line, code_snippet: f.code_snippet || "" });
            g.count++;
            if (f.source === "both" || f.source === "pattern") {
                g.source = f.source === "both" ? "both" : g.source;
            }
        }
    }

    const severityOrder = { HIGH: 0, MEDIUM: 1, LOW: 2 };
    return Array.from(groups.values()).sort((a, b) => {
        const sevDiff = (severityOrder[a.severity] ?? 3) - (severityOrder[b.severity] ?? 3);
        if (sevDiff !== 0) return sevDiff;
        return b.count - a.count;
    });
}

// --- Main scanner ---
async function scanRepo(repoUrl) {
    console.log(`\n🔍 Starting scan: ${repoUrl}\n`);

    const { owner, repo } = parseGitHubUrl(repoUrl);
    const repoName = `${owner}/${repo}`;

    const { branch, files } = await getRepoTree(owner, repo);

    const prioritized = R.prioritizeFiles(files);
    const topFiles = prioritized.slice(0, MAX_FILES);
    console.log(`\n📊 Scan plan: ${topFiles.length} of ${files.length} files (prioritized)`);

    const withContent = await getAllFileContents(owner, repo, branch, topFiles);

    console.log(`\n🔬 Analyzing ${withContent.length} files...\n`);

    const breaker = new R.CircuitBreaker();
    const results = [];

    for (const file of withContent) {
        console.log(`[${results.length + 1}/${withContent.length}] ${file.path}`);

        // Pattern layer
        const patternFindings = scanWithPatterns(file.path, file.content);
        if (patternFindings.length > 0) {
            console.log(`   🔷 Pattern layer: ${patternFindings.length} finding(s)`);
        }

        // Skip LLM for test/config files
        const sendToLLM = P.shouldSendToLLM(file.path);
        const analyzeFn = sendToLLM
            ? (text, startLine, path) => analyzeChunk(text, startLine, path, repoName)
            : async () => [];

        if (!sendToLLM) {
            console.log(`   ⏭️  Skipping LLM (non-prod file)`);
        }

        const r = await R.scanFileResilient({
            path: file.path,
            content: file.content,
            patternFindings,
            analyzeChunk: analyzeFn,
            breaker,
            delayMs: 2000
        });

        // Verify LLM findings against the actual file
        r.findings = P.applyVerification(r.findings, file.content);

        // Cap severity for non-prod files
        r.findings = P.adjustForNonProd(r.findings, file.path);

        results.push(r);

        if (r.aborted) {
            console.log(`\n⚠️  Scan aborted. Saving partial report.`);
            break;
        }
    }

    R.printCoverage(results);

    // Merge + aggregate + group
    const allFindings = results.flatMap(r => r.findings);
    const merged = mergeFindings(allFindings);
    const unique = aggregateFindings(merged);
    const grouped = groupFindings(unique);

    const bySource = {
        pattern: unique.filter(f => f.source === "pattern").length,
        llm: unique.filter(f => f.source === "llm").length,
        both: unique.filter(f => f.source === "both").length
    };
    const bySeverity = {
        HIGH: unique.filter(f => f.severity === "HIGH").length,
        MEDIUM: unique.filter(f => f.severity === "MEDIUM").length,
        LOW: unique.filter(f => f.severity === "LOW").length
    };
    const coverage = {
        total: results.length,
        scanned: results.filter(r => r.status === "scanned").length,
        partial: results.filter(r => r.status === "partial").length,
        failed: results.filter(r => r.status === "failed").length,
        skipped: results.filter(r => r.status === "skipped").length
    };
    const scanId = await saveScanReport({
    repoUrl,
    repo: repoName,
    branch,
    totalFiles: files.length,
    rawFindings: unique.length,
    bySeverity,
    bySource,
    coverage,
    findings: grouped
});

    return {
        repo: repoName,
        branch,
        scannedFiles: coverage.scanned + coverage.partial,
        totalFiles: files.length,
        rawFindings: unique.length,
        groupedFindings: grouped.length,
        bySeverity,
        bySource,
        coverage,
        scanTime: new Date().toISOString(),
        findings: grouped,
	scanId
    };
}

module.exports = { scanRepo };

// --- Run standalone ---
if (require.main === module) {
    const testUrl = process.argv[2] || "https://github.com/superwavvy/guardpr-test";

    scanRepo(testUrl)
        .then(report => {
            console.log(`\n${'='.repeat(60)}`);
            console.log(`📋 SCAN REPORT: ${report.repo}`);
            console.log(`${'='.repeat(60)}`);
            console.log(`Files scanned: ${report.scannedFiles} / ${report.totalFiles}`);
            console.log(`Raw findings: ${report.rawFindings}`);
            console.log(`Grouped findings: ${report.groupedFindings}`);
            console.log(`\nBy severity:`);
            console.log(`  🔴 HIGH:   ${report.bySeverity.HIGH}`);
            console.log(`  🟡 MEDIUM: ${report.bySeverity.MEDIUM}`);
            console.log(`  🟢 LOW:    ${report.bySeverity.LOW}`);
            console.log(`\nBy source:`);
            console.log(`  🔷 Pattern (deterministic): ${report.bySource.pattern}`);
            console.log(`  🔶 LLM (contextual):        ${report.bySource.llm}`);
            console.log(`  🟣 Both (corroborated):     ${report.bySource.both}`);
            console.log(`\nFindings:\n`);

            report.findings.forEach(f => {
                const badge = f.source === "pattern" ? "🔷"
                            : f.source === "both"    ? "🟣"
                            : "🔶";
                const corrob = f.source === "both" ? " (corroborated)" : "";
                const countLabel = f.count > 1 ? ` — seen in ${f.count} files` : "";
                console.log(`  ${badge} [${f.severity}] ${f.type}${countLabel}${corrob}`);
                console.log(`     ${f.cwe_id} | ${f.owasp_category}`);
                console.log(`     ${f.description}`);
                if (f.count > 1) {
                    f.occurrences.slice(0, 5).forEach(o => {
                        console.log(`       • ${o.file}:${o.line}`);
                    });
                    if (f.occurrences.length > 5) {
                        console.log(`       • ... and ${f.occurrences.length - 5} more`);
                    }
                } else {
                    console.log(`     File: ${f.file}:${f.line}`);
                }
                console.log(``);
            });

            fs.writeFileSync('report.json', JSON.stringify(report, null, 2));
            console.log(`💾 Full report saved to report.json`);
        })
        .catch(err => console.error("❌ Scan failed:", err.message));
}
