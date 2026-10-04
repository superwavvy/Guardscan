const { Octokit } = require("@octokit/rest");

const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });

// --- 1. Parse a GitHub URL into owner/repo ---
function parseGitHubUrl(url) {
    const cleaned = url.replace(/^(https?:\/\/)?(www\.)?github\.com\//, '').replace(/\.git$/, '').replace(/\/$/, '');
    const parts = cleaned.split('/');
    if (parts.length < 2) throw new Error("Invalid GitHub URL. Expected format: https://github.com/owner/repo");
    return { owner: parts[0], repo: parts[1] };
}

// --- 2. Detect language from file extension ---
function detectLanguage(filePath) {
    const ext = filePath.split('.').pop().toLowerCase();
    const map = {
        js: 'JavaScript', jsx: 'React (JSX)', ts: 'TypeScript', tsx: 'React (TSX)',
        py: 'Python', java: 'Java', go: 'Go', rb: 'Ruby',
        php: 'PHP', sol: 'Solidity', rs: 'Rust', c: 'C', cpp: 'C++',
        cs: 'C#', swift: 'Swift', kt: 'Kotlin'
    };
    return map[ext] || 'Unknown';
}

// --- 3. Only allow code files we can meaningfully scan ---
function isCodeFile(filePath) {
    const codeExtensions = ['js', 'jsx', 'ts', 'tsx', 'py', 'java', 'go', 'rb', 'php', 'sol', 'rs', 'c', 'cpp', 'cs'];
    const ext = filePath.split('.').pop().toLowerCase();
    return codeExtensions.includes(ext);
}

// --- 4. Fetch the FULL file tree (no slicing) ---
async function getRepoTree(owner, repo) {
    console.log(`📂 Fetching file tree for ${owner}/${repo}...`);

    const repoInfo = await octokit.repos.get({ owner, repo });
    const branch = repoInfo.data.default_branch;
    console.log(`   Default branch: ${branch}`);

    const treeResponse = await octokit.git.getTree({
        owner, repo,
        tree_sha: branch,
        recursive: "true"
    });

    // Noise folders we skip entirely
    const skipPatterns = [
        /^node_modules\//i, /^dist\//i, /^build\//i, /^coverage\//i,
        /^\.next\//i, /^\.git\//i, /^vendor\//i
    ];

    const MAX_FILE_SIZE = 50 * 1024; // 50KB

    const codeFiles = treeResponse.data.tree
        .filter(item => item.type === "blob")
        .filter(item => isCodeFile(item.path))
        .filter(item => !skipPatterns.some(p => p.test(item.path)))
        .filter(item => item.size && item.size <= MAX_FILE_SIZE)
        .map(item => ({
            path: item.path,
            size: item.size,
            language: detectLanguage(item.path)
        }));

    console.log(`   Found ${codeFiles.length} scannable code files`);
    return { branch, files: codeFiles };
}

// --- 5. Fetch raw content of a single file ---
async function getFileContent(owner, repo, branch, path) {
    try {
        const url = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${path}`;
        const response = await fetch(url);
        if (!response.ok) return null;
        return await response.text();
    } catch (e) {
        console.error(`Failed to fetch ${path}:`, e.message);
        return null;
    }
}

// --- 6. Fetch content for a specific list of files ---
async function getAllFileContents(owner, repo, branch, files) {
    console.log(`📥 Fetching ${files.length} files...`);
    const results = [];
    const CONCURRENCY = 10;

    for (let i = 0; i < files.length; i += CONCURRENCY) {
        const batch = files.slice(i, i + CONCURRENCY);
        const batchResults = await Promise.all(
            batch.map(async (file) => {
                const content = await getFileContent(owner, repo, branch, file.path);
                return content ? { ...file, content } : null;
            })
        );
        results.push(...batchResults.filter(Boolean));
        console.log(`   Fetched ${Math.min(i + CONCURRENCY, files.length)} / ${files.length}`);
    }

    return results;
}

module.exports = {
    parseGitHubUrl,
    detectLanguage,
    isCodeFile,
    getRepoTree,
    getFileContent,
    getAllFileContents
};
