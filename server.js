require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { scanRepo } = require('./scanner.js');

const app = express();
const PORT = process.env.PORT || 8100;
const API_KEY = process.env.API_KEY;

app.use(express.json({ limit: '1mb' }));
app.use(cors({
    origin: [
        'http://localhost:3000',
        /\.vercel\.app$/,
        /\.superwavvy\.xyz$/
    ],
    methods: ['POST', 'GET']
}));

const scanLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    message: { error: 'Rate limit reached. Try again in an hour.' },
    standardHeaders: true,
    legacyHeaders: false
});
app.set('trust proxy', 1);

app.get('/', (req, res) => {
    res.json({ status: 'ok', service: 'guardscan-scanner' });
});

app.post('/scan', scanLimiter, (req, res) => {
    const auth = req.headers['x-api-key'];
    if (API_KEY && auth !== API_KEY) {
        return res.status(401).json({ error: 'Unauthorized' });
    }

    const { repoUrl } = req.body;
    if (!repoUrl || !repoUrl.includes('github.com')) {
        return res.status(400).json({ error: 'Invalid GitHub URL' });
    }

    console.log(`\n📥 Scan request: ${repoUrl} from ${req.ip}`);

    // Respond immediately — scan runs in background
    res.json({
        status: 'started',
        repoUrl,
        message: 'Scan queued. Results will appear in your scan history shortly.'
    });

    // Fire and forget
    scanRepo(repoUrl)
        .then((report) => {
            console.log(`✅ Scan complete: ${report.repo} (${report.totalVulnerabilities} findings)`);
        })
        .catch((error) => {
            console.error(`❌ Scan failed for ${repoUrl}:`, error.message);
        });
});

app.listen(PORT, () => {
    console.log(`🛡️  GuardScan scanner running on port ${PORT}`);
});
