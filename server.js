require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { scanRepo } = require('./scanner.js');

const app = express();
const scanLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5, message: { error: 'Rate limit reached. Try again in an hour.' }, standardHeaders: true, legacyHeaders: false });
app.set('trust proxy', 1);
const PORT = process.env.PORT || 8100;
const API_KEY = process.env.API_KEY; // shared secret with Vercel

app.use(express.json({ limit: '1mb' }));
app.use(cors({
    origin: [
        'http://localhost:3000',
        'https://guardscan.vercel.app', // your Vercel domain, adjust
        /\.vercel\.app$/,
        /\.superwavvy\.xyz$/
    ],
    methods: ['POST', 'GET']
}));

// Health check
app.get('/', (req, res) => {
    res.json({ status: 'ok', service: 'guardscan-scanner' });
});

// Main scan endpoint
app.post('/scan', scanLimiter, async (req, res) => {
    // Auth check
    const auth = req.headers['x-api-key'];
    if (API_KEY && auth !== API_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const { repoUrl } = req.body;
    if (!repoUrl || !repoUrl.includes('github.com')) {
        return res.status(400).json({ error: 'Invalid GitHub URL' });
    }

    console.log(`\n📥 Scan request: ${repoUrl} from ${req.ip}`);

    try {
        const report = await scanRepo(repoUrl);

        if (!report.scanId) {
            return res.status(500).json({ error: 'Scan completed but no scanId returned' });
        }

        res.json({
            scanId: report.scanId,
            repo: report.repo,
            totalVulnerabilities: report.totalVulnerabilities,
            cached: report.cached || false,
            bySeverity: report.bySeverity,
            coverage: report.coverage
        });
    } catch (error) {
        console.error('Scan error:', error.message);
        res.status(500).json({ error: error.message });
    }
});

app.listen(PORT, () => {
    console.log(`🛡️  GuardScan scanner running on port ${PORT}`);
});
