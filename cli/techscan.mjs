#!/usr/bin/env node
// Batch scanner reusing the extension's collectors and engine in headless Chromium.
// Only scan targets you are authorised to test (bug bounty scope, your own sites).
import fs from 'node:fs';
import { parseArgs } from 'node:util';
import { pathToFileURL } from 'node:url';
import { collectPage, collectGlobals, collectBundles } from '../collector.js';
import { detect } from '../engine.js';
import { huntAll } from '../hunt.js';

const HELP = `Usage: techscan [options] <target...>
  -i, --input <file>        read targets from a file (one per line, # comments)
  -o, --output <file>       write results to a file instead of stdout
  -f, --format <jsonl|csv>  output format (default jsonl)
  -c, --concurrency <n>     pages scanned in parallel (default 4)
      --deep                re-read scripts for hashes, banners and source maps
      --cve                 query OSV (packages) and NVD (server software)
      --timeout <ms>        navigation timeout (default 30000)
  -h, --help
Targets without a scheme get https://.`;

const HEADER_NAMES = new Set([
  'server',
  'x-powered-by',
  'x-vercel-id',
  'x-vercel-cache',
  'cf-ray',
  'x-aspnet-version',
]);

export function normalizeTarget(raw) {
  const s = raw.trim();
  if (!s || s.startsWith('#')) return null;
  try {
    const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : 'https://' + s);
    return /^https?:$/.test(url.protocol) ? url.href : null;
  } catch {
    return null;
  }
}

// NVD allows 5 keyless requests per 30 s; space them across the whole run.
export function throttleNvd(fetchFn, gapMs = 6500) {
  let next = 0;
  return async (url, init) => {
    if (String(url).includes('services.nvd.nist.gov')) {
      const wait = Math.max(0, next - Date.now());
      next = Math.max(Date.now(), next) + gapMs;
      if (wait) await new Promise((r) => setTimeout(r, wait));
    }
    return fetchFn(url, init);
  };
}

export function memoryCache() {
  const state = new Map();
  return {
    get: async (key) => ({ [key]: state.get(key) }),
    set: async (data) => {
      for (const [k, v] of Object.entries(data)) state.set(k, v);
    },
  };
}

export function toCsv(results) {
  const esc = (v) => (/[",\n]/.test(v) ? `"${v.replace(/"/g, '""')}"` : v);
  const rows = [['target', 'site', 'technology', 'versions', 'categories', 'cves', 'error']];
  for (const r of results) {
    if (r.error) {
      rows.push([r.target, '', '', '', '', '', r.error]);
      continue;
    }
    for (const t of r.technologies) {
      const cves = (r.cveHunt?.queries || [])
        .filter((q) => q.technology === t.name)
        .flatMap((q) => q.advisories.map((a) => a.cves[0] || a.id));
      rows.push([
        r.target,
        r.site,
        t.name,
        t.versions.join(' / '),
        t.categories.join('; '),
        cves.join(' '),
        '',
      ]);
    }
  }
  return rows.map((row) => row.map((v) => esc(String(v))).join(',')).join('\n') + '\n';
}

export async function scanTarget(
  context,
  target,
  { deep = false, cve = false, timeout = 30000, hunt = {} } = {},
) {
  const page = await context.newPage();
  try {
    const response = await page.goto(target, { waitUntil: 'load', timeout });
    // Let late scripts register globals, as a person would before clicking the extension.
    await page.waitForTimeout(1500);
    const headers = Object.entries((await response?.allHeaders()) || {})
      .filter(([name]) => HEADER_NAMES.has(name))
      .map(([name, value]) => ({ name, value: value.slice(0, 200) }));
    const [snapshot, globals, bundles] = await Promise.all([
      page.evaluate(collectPage),
      page.evaluate(collectGlobals),
      deep ? page.evaluate(collectBundles) : [],
    ]);
    const finalUrl = new URL(page.url());
    const result = {
      target,
      site: finalUrl.origin,
      status: response?.status() ?? null,
      scannedAt: new Date().toISOString(),
      headersAvailable: headers.length > 0,
      technologies: detect({ ...snapshot, bundles }, globals, headers),
    };
    if (cve) result.cveHunt = await huntAll(result.technologies, { nvd: true, ...hunt });
    return result;
  } catch (e) {
    return { target, error: e.message.split('\n')[0] };
  } finally {
    await page.close();
  }
}

async function main(argv) {
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      input: { type: 'string', short: 'i' },
      output: { type: 'string', short: 'o' },
      format: { type: 'string', short: 'f', default: 'jsonl' },
      concurrency: { type: 'string', short: 'c', default: '4' },
      deep: { type: 'boolean', default: false },
      cve: { type: 'boolean', default: false },
      timeout: { type: 'string', default: '30000' },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });
  if (values.help) return console.log(HELP);
  const raw = [
    ...positionals,
    ...(values.input ? fs.readFileSync(values.input, 'utf8').split('\n') : []),
  ];
  const targets = [...new Set(raw.map(normalizeTarget).filter(Boolean))];
  if (!targets.length) throw new Error('No valid targets. ' + HELP);
  if (!['jsonl', 'csv'].includes(values.format)) throw new Error('--format must be jsonl or csv');

  let chromium;
  try {
    ({ chromium } = await import('playwright'));
  } catch {
    throw new Error('Playwright is required: npm i playwright && npx playwright install chromium');
  }
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({ ignoreHTTPSErrors: false });
  const hunt = { fetchFn: throttleNvd(fetch), cache: memoryCache() };
  const out = values.output ? fs.createWriteStream(values.output) : process.stdout;
  const results = [];
  let cursor = 0,
    done = 0;
  const worker = async () => {
    while (cursor < targets.length) {
      const target = targets[cursor++];
      const r = await scanTarget(context, target, {
        deep: values.deep,
        cve: values.cve,
        timeout: Number(values.timeout),
        hunt,
      });
      results.push(r);
      if (values.format === 'jsonl') out.write(JSON.stringify(r) + '\n');
      process.stderr.write(
        `[${++done}/${targets.length}] ${target} ${r.error ? 'ERROR ' + r.error : r.technologies.length + ' technologies'}\n`,
      );
    }
  };
  try {
    await Promise.all(Array.from({ length: Math.max(1, Number(values.concurrency) || 4) }, worker));
  } finally {
    await browser.close();
  }
  if (values.format === 'csv') out.write(toCsv(results));
  if (values.output) out.end();
}

const invoked = process.argv[1] && pathToFileURL(fs.realpathSync(process.argv[1])).href;
if (invoked === import.meta.url)
  main(process.argv.slice(2)).catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
