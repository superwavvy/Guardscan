# 🛡️ GuardScan

An AI-powered security scanner that reads your GitHub repo and finds the OWASP Top 10 vulnerabilities before attackers do.

<sub>[Try it live →](https://guardscan-nine.vercel.app)</sub>
---

## What It Does

Paste a GitHub URL. 30 seconds later, you get a report listing security vulnerabilities found in the code, sorted by severity.

It is **not** a replacement for a professional security audit. It's a first-pass triage tool — a smoke detector, not a fire inspector.

## Features

- **Two detection layers** — deterministic regex patterns + contextual LLM analysis
- **OWASP Top 10:2025** coverage
- **CWE-mapped findings** with severity and confidence scores
- **Structured output** — file, line, code snippet, description, and fix suggestion
- **Coverage honesty** — reports scanned/partial/failed/skipped files separately
- **Rate-limit resilient** — exponential backoff, circuit breaker, chunking
- **Scan history** — compares runs over time (Supabase-backed)

## Architecture

```
User pastes GitHub URL
     ↓
[Vercel Frontend]  → POST /api/scan
     ↓
[Alwaysdata Scanner]  → fetches repo, runs 2-layer analysis
     ↓
[Supabase]  → stores scan + findings
     ↓
[Vercel Frontend]  → renders report
```

| Layer | Stack |
|:---|:---|
| Frontend | Next.js 16, TypeScript, Tailwind v4, IBM Plex Mono |
| Backend | Node.js, Express, Ethers v6, Octokit |
| Analysis | Deterministic regex + Groq LLM (`openai/gpt-oss-120b`) |
| Storage | Supabase (Postgres) |
| Hosting | Vercel (UI) + Alwaysdata (scanner) |

## Repo Structure

```
guardscan/
├── scanner.js              # Orchestrator
├── analyzer.js             # LLM analysis + CWE mapping
├── patterns.js             # Deterministic regex rules
├── resilience.js           # Retry, chunking, circuit breaker
├── fetcher.js              # GitHub API client
├── guardscan-patch.js      # SQL rule refinement + LLM verification
├── db.js                   # Supabase writes
├── server.js               # Express HTTP wrapper
└── ui/                     # Next.js frontend
```

See [TECHNICAL_OVERVIEW.md](./TECHNICAL_OVERVIEW.md) for the deep dive.

## Validation

**OWASP Juice Shop** — deliberately vulnerable training app:
- 30 files scanned, 26 unique findings

**expressjs/express** — production repo, already audited:
- 30 files scanned, 15 findings
- Rediscovered bug classes matching **CVE-2024-29041** (Host Header Injection) and **CVE-2024-43796** (Path Traversal in res.download)

## Local Development

### Scanner backend

```bash
cd guardscan
npm install
cp .env.example .env
node server.js
```

Runs on port 8100 by default.

### UI frontend

In a separate terminal:

```bash
cd guardscan/ui
npm install
cp .env.example .env.local
npm run dev
```

Open http://localhost:3000.

## Environment Variables

### Scanner (`.env` in repo root)

```
API_KEY=random_hex_string
GROQ_API_KEY=gsk_...
GITHUB_TOKEN=ghp_...
ARBITRUM_RPC=https://arb-mainnet.g.alchemy.com/v2/...
SUPABASE_URL=https://....supabase.co
SUPABASE_ANON_KEY=eyJ...
```

### UI (`ui/.env.local`)

```
NEXT_PUBLIC_SUPABASE_URL=https://....supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...
SCANNER_URL=https://guardscan.alwaysdata.net
SCANNER_API_KEY=same_as_backend_api_key
```

## Known Limitations

- **LLM non-determinism** — running the same scan twice may produce slightly different results. Direct pattern matches (SQL injection, hardcoded secrets) are stable; contextual findings (auth design smells) may vary.
- **30-file cap per scan** — MVP tradeoff for speed and API rate limits.
- **False positives possible** — every finding should be manually verified before acting on it.
- **Not a replacement for professional audit** — this is a triage tool.

## License

MIT
