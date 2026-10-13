// End-to-end check in real Chromium: loads the unpacked extension, serves a local fixture site
// and runs the collectors + engine through chrome.scripting, as the popup does.
// Run: node scripts/e2e-extension.mjs   (needs `npx playwright install chromium` and internet
// once, to download jQuery 3.4.1 for the hash check)
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { chromium } from 'playwright';

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');
const jquery = await (await fetch('https://code.jquery.com/jquery-3.4.1.min.js')).text();
const bundle =
  '/*! @license DOMPurify 2.0.17 | (c) Cure53 */\nconsole.log(1);\n//# sourceMappingURL=app.js.map';
const map = JSON.stringify({
  version: 3,
  sources: ['webpack://shop/node_modules/.pnpm/axios@0.21.0/node_modules/axios/lib/axios.js'],
  mappings: '',
});
const pages = {
  '/': [
    'text/html',
    '<!doctype html><meta name="generator" content="WordPress 6.4.2"><script src="/vendor.js"></script><script src="/app.js"></script><link rel="stylesheet" href="/wp-content/plugins/contact-form-7/style.css?ver=5.8.4"><h1>fixture</h1>',
  ],
  '/vendor.js': ['text/javascript', jquery],
  '/app.js': ['text/javascript', bundle],
  '/app.js.map': ['application/json', map],
  '/wp-content/plugins/contact-form-7/style.css': ['text/css', 'h1{color:red}'],
};
const server = http.createServer((req, res) => {
  const page = pages[new URL(req.url, 'http://x').pathname];
  if (!page) return res.writeHead(404).end();
  res.writeHead(200, {
    'content-type': page[0],
    server: 'nginx/1.24.0',
    'x-powered-by': 'PHP/8.1.2',
  });
  res.end(page[1]);
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const site = `http://127.0.0.1:${server.address().port}/`;

// Copy the extension and pre-grant the fixture host, which a user would grant via the prompt.
const ext = fs.mkdtempSync(path.join(os.tmpdir(), 'techlens-ext-'));
for (const entry of fs.readdirSync(root))
  if (!['node_modules', '.git', 'tests', 'scripts', 'cli'].includes(entry))
    fs.cpSync(path.join(root, entry), path.join(ext, entry), { recursive: true });
const manifest = JSON.parse(fs.readFileSync(path.join(ext, 'manifest.json'), 'utf8'));
manifest.host_permissions = ['http://127.0.0.1/*'];
fs.writeFileSync(path.join(ext, 'manifest.json'), JSON.stringify(manifest));

const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'techlens-profile-'));
const context = await chromium.launchPersistentContext(profile, {
  channel: 'chromium',
  headless: true,
  args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
});
try {
  const worker = context.serviceWorkers()[0] || (await context.waitForEvent('serviceworker'));
  const id = new URL(worker.url()).host;
  const target = await context.newPage();
  await target.goto(site);

  const ui = await context.newPage();
  const errors = [];
  ui.on('pageerror', (e) => errors.push(e.message));
  ui.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  await ui.goto(`chrome-extension://${id}/popup.html?panel`);
  await ui.waitForTimeout(500);
  assert.equal(await ui.evaluate(() => document.body.classList.contains('panel')), true);

  // On a fresh profile the webRequest listener can miss the very first navigation. Users always
  // reload after granting site access, so do the same once if no headers were stored.
  const headersStored = () =>
    ui.evaluate(async (url) => {
      const [tab] = await chrome.tabs.query({ url: url + '*' });
      for (let i = 0; i < 30; i++) {
        if ((await chrome.storage.session.get('headers:' + tab.id))['headers:' + tab.id])
          return true;
        await new Promise((r) => setTimeout(r, 100));
      }
      return false;
    }, site);
  if (!(await headersStored())) {
    await target.reload();
    assert.ok(await headersStored(), 'background.js stored response headers after reload');
  }

  const result = await ui.evaluate(async (url) => {
    const { collectPage, collectGlobals, collectBundles } = await import('./collector.js');
    const { detect } = await import('./engine.js');
    const [tab] = await chrome.tabs.query({ url: url + '*' });
    const target = { tabId: tab.id };
    const [[page], [globals], [bundles]] = await Promise.all([
      chrome.scripting.executeScript({ target, func: collectPage }),
      chrome.scripting.executeScript({ target, world: 'MAIN', func: collectGlobals }),
      chrome.scripting.executeScript({ target, func: collectBundles }),
    ]);
    const headers = (await chrome.storage.session.get('headers:' + tab.id))['headers:' + tab.id];
    await chrome.sidePanel.setOptions({ path: 'popup.html?panel', enabled: true });
    return {
      technologies: detect(
        { ...page.result, bundles: bundles.result },
        globals.result,
        headers?.headers || [],
      ),
      bundles: bundles.result,
      panelPath: (await chrome.sidePanel.getOptions({})).path,
    };
  }, site);
  const find = (name) => result.technologies.find((t) => t.name === name);
  console.log(result.technologies.map((t) => `${t.name} ${t.versions.join('/')}`).join('\n'));
  assert.deepEqual(find('jQuery')?.versions, ['3.4.1'], 'jQuery from hash (and global)');
  assert.ok(find('jQuery').evidence.some((e) => e.startsWith('Bundle hash:')));
  assert.deepEqual(find('DOMPurify')?.versions, ['2.0.17'], 'banner');
  assert.deepEqual(find('npm: axios')?.versions, ['0.21.0'], 'source map');
  assert.deepEqual(find('Nginx')?.versions, ['1.24.0'], 'server header via webRequest');
  assert.deepEqual(find('PHP')?.versions, ['8.1.2']);
  assert.deepEqual(find('WordPress')?.versions, ['6.4.2']);
  assert.deepEqual(find('WP plugin: contact-form-7')?.versions, ['5.8.4']);
  assert.ok(result.panelPath.endsWith('popup.html?panel'), result.panelPath);
  // 127.0.0.1 is a secure context, so crypto.subtle hashing works; public HTTP sites skip it.
  assert.ok(result.bundles.every((b) => !b.error));
  assert.deepEqual(errors, []);
  console.log('\ne2e OK');
} finally {
  await context.close();
  server.close();
}
