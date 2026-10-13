// Renders the popup against a local demo site and saves screenshots to docs/.
// Run: node scripts/screenshots.mjs   (needs Playwright Chromium and internet for jQuery/CVE data)
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { chromium } from 'playwright';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const jquery = await (await fetch('https://code.jquery.com/jquery-3.4.1.min.js')).text();
const html = `<!doctype html><title>Demo shop</title>
<meta name="generator" content="WordPress 6.4.2"><meta property="og:title" content="Demo">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">
<link rel="stylesheet" href="/wp-content/plugins/contact-form-7/style.css?ver=5.8.4">
<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.4.1"></script>
<script src="https://www.googletagmanager.com/gtag/js?id=G-DEMO123"></script>
<h1>Demo</h1>`;
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://x');
  res.setHeader('server', 'nginx/1.24.0');
  res.setHeader('x-powered-by', 'PHP/8.1.2');
  if (url.pathname.endsWith('jquery.min.js')) return res.end(jquery);
  if (url.pathname.endsWith('.css')) return res.end('h1{color:#333}');
  res.setHeader('content-type', 'text/html');
  res.end(html);
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const site = `http://127.0.0.1:${server.address().port}/`;

const ext = fs.mkdtempSync(path.join(os.tmpdir(), 'techlens-shot-'));
for (const entry of fs.readdirSync(root))
  if (!['node_modules', '.git', 'tests', 'scripts', 'cli', 'docs'].includes(entry))
    fs.cpSync(path.join(root, entry), path.join(ext, entry), { recursive: true });
const manifest = JSON.parse(fs.readFileSync(path.join(ext, 'manifest.json'), 'utf8'));
// Pre-grant what a user would grant through prompts.
manifest.host_permissions = [
  'http://127.0.0.1/*',
  'https://api.osv.dev/*',
  'https://services.nvd.nist.gov/*',
];
fs.writeFileSync(path.join(ext, 'manifest.json'), JSON.stringify(manifest));

const context = await chromium.launchPersistentContext(
  fs.mkdtempSync(path.join(os.tmpdir(), 'p-')),
  {
    channel: 'chromium',
    headless: true,
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  },
);
try {
  const worker = context.serviceWorkers()[0] || (await context.waitForEvent('serviceworker'));
  const id = new URL(worker.url()).host;
  const target = await context.newPage();
  await target.goto(site);
  await target.reload(); // headers are only recorded once the listener is live
  const popup = await context.newPage();
  // The popup scans the active tab; point it at the demo site instead of itself.
  await popup.addInitScript((url) => {
    const query = chrome.tabs.query.bind(chrome.tabs);
    chrome.tabs.query = async (q) =>
      q.active ? (await query({})).filter((t) => t.url?.startsWith(url)) : query(q);
  }, site);
  await popup.setViewportSize({ width: 400, height: 600 });
  await popup.goto(`chrome-extension://${id}/popup.html`);
  await popup.waitForFunction(() => document.getElementById('stat-total').textContent !== '0');
  await popup.screenshot({ path: path.join(root, 'docs/screenshot-tech.png'), fullPage: true });
  await popup.click('#tab-cve');
  await popup.click('#hunt');
  await popup.waitForFunction(
    () => /khớp phiên bản/.test(document.getElementById('hunt-status').textContent),
    null,
    { timeout: 90000 },
  );
  await popup.evaluate(() =>
    document.querySelector('#hunt-results details:nth-of-type(2)')?.setAttribute('open', ''),
  );
  await popup.screenshot({ path: path.join(root, 'docs/screenshot-cve.png'), fullPage: true });
  console.log('saved docs/screenshot-tech.png, docs/screenshot-cve.png');
} finally {
  await context.close();
  server.close();
}
