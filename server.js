/**
 * DEVS legacy — SSRF challenge
 *
 * Main app:
 *  - Serves static frontend at /
 *  - Provides /api/fetch?url=<url> which performs a server-side HTTP GET and returns body
 *
 * Internal debug service:
 *  - Listens only on 127.0.0.1:8000 and returns the flag at /internal/flag
 *
 * Vulnerability (intentional): the fetch endpoint performs a naive blacklist:
 *    disallow hostname strings that contain "127.0.0.1", "localhost" or "::1"
 * but it does NOT block decimal, octal or hex-encoded IPv4 representations.
 *
 * Solvers must use an alternate IP notation (e.g., decimal 2130706433 for 127.0.0.1)
 * to reach the internal service.
 */

const express = require('express');
const http = require('http');
const https = require('https');
const fetch = require('node-fetch'); // v2
const path = require('path');
const fs = require('fs');
const morgan = require('morgan');
const cors = require('cors');

const FLAG = process.env.FLAG || 'FLAG{ssrf_decimal_wrap}';
const MAIN_PORT = process.env.PORT || 3000;
const INTERNAL_PORT = 8000; // bound to localhost in internal service

/**********************
 * Internal debug service (binds to 127.0.0.1:8000)
 * This simulates an internal-only admin endpoint that should not be reachable from the public.
 **********************/
const internalApp = express();

internalApp.get('/internal/flag', (req, res) => {
  // This endpoint should not be publicly available; it's only accessible server-side.
  res.setHeader('Content-Type', 'text/plain');
  res.send(`admin-secret: ${FLAG}\n`);
});

internalApp.get('/internal/info', (req, res) => {
  res.json({ name: 'internal-debug', uptime: process.uptime() });
});

// Only listen on loopback
internalApp.listen(INTERNAL_PORT, '127.0.0.1', () => {
  console.log(`Internal debug service listening on 127.0.0.1:${INTERNAL_PORT}`);
});

/**********************
 * Public app (challenge surface)
 **********************/
const app = express();
app.use(morgan('tiny'));
app.use(cors());
app.use(express.json());

// Serve static frontend (web/)
app.use('/', express.static(path.join(__dirname, 'web')));

/**
 * Naive blacklist based fetch endpoint (intentionally imperfect)
 * Usage: /api/fetch?url=<url>
 *
 * Checks: only rejects if url contains the literal strings "localhost", "127.0.0.1", or "::1"
 * That means alternate IP encodings (decimal, octal, hex) may bypass.
 */
app.get('/api/fetch', async (req, res) => {
  const url = (req.query.url || '').trim();
  if (!url) return res.status(400).json({ error: 'url parameter required' });

  // naive forbidlist
  const lowered = url.toLowerCase();
  if (lowered.includes('localhost') || lowered.includes('127.0.0.1') || lowered.includes('::1')) {
    return res.status(403).json({ error: 'local addresses are not allowed' });
  }

  // Basic safety: only allow http/https schemes (but still vulnerable to SSRF inside those)
  if (!/^https?:\/\//i.test(url)) {
    return res.status(400).json({ error: 'only http and https allowed' });
  }

  try {
    // follow redirects and return the text body (small requests only)
    const r = await fetch(url, { redirect: 'follow', timeout: 5000 });
    const text = await r.text();

    // truncate to avoid huge responses
    const snippet = text.length > 2000 ? text.slice(0, 2000) + '\n\n...[truncated]' : text;
    return res.json({ status: r.status, url: url, body: snippet });
  } catch (e) {
    return res.status(500).json({ error: 'fetch failed', detail: String(e) });
  }
});

// convenience: list the public endpoints
app.get('/api/info', (req, res) => {
  res.json({
    name: 'DEVS legacy (SSRF demo)',
    endpoints: ['/api/fetch?url=...', '/api/info', '/api/health'],
    note: 'Public fetch tool blocks obvious local hostnames but not all IP encodings.'
  });
});

app.get('/api/health', (req,res) => res.send('ok'));

app.listen(MAIN_PORT, () => {
  console.log(`Public app listening on port ${MAIN_PORT}`);
  console.log('Endpoints: /api/fetch?url=<url>    (naive protection)');
});
