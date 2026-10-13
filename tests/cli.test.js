import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeTarget, toCsv, throttleNvd, memoryCache } from '../cli/techscan.mjs';

test('targets get https:// by default and junk lines are dropped', () => {
  assert.equal(normalizeTarget('example.com'), 'https://example.com/');
  assert.equal(normalizeTarget(' http://a.test/x '), 'http://a.test/x');
  for (const s of ['', '# comment', 'ftp://a.test', 'javascript:alert(1)'])
    assert.equal(normalizeTarget(s), null);
});

test('CSV has one row per technology, CVE ids and escaped fields', () => {
  const csv = toCsv([
    {
      target: 'https://a.test/',
      site: 'https://a.test',
      technologies: [
        { name: 'jQuery', versions: ['3.4.1'], categories: ['JavaScript libraries', 'x,y'] },
      ],
      cveHunt: {
        queries: [
          { technology: 'jQuery', advisories: [{ id: 'GHSA-1', cves: ['CVE-2020-11022'] }] },
        ],
      },
    },
    { target: 'https://down.test/', error: 'net::ERR_NAME_NOT_RESOLVED' },
  ]);
  const lines = csv.trim().split('\n');
  assert.equal(lines.length, 3);
  assert.equal(
    lines[1],
    'https://a.test/,https://a.test,jQuery,3.4.1,"JavaScript libraries; x,y",CVE-2020-11022,',
  );
  assert.match(lines[2], /ERR_NAME_NOT_RESOLVED$/);
});

test('NVD calls are spaced across the run while other hosts are not delayed', async () => {
  const times = [];
  const fetchFn = throttleNvd(async (url) => times.push([String(url), Date.now()]), 50);
  await Promise.all([
    fetchFn('https://services.nvd.nist.gov/a'),
    fetchFn('https://services.nvd.nist.gov/b'),
    fetchFn('https://api.osv.dev/v1/query'),
  ]);
  const nvd = times.filter(([u]) => u.includes('nvd')).map(([, t]) => t);
  assert.ok(nvd[1] - nvd[0] >= 45);
  const cache = memoryCache();
  await cache.set({ k: 1 });
  assert.deepEqual(await cache.get('k'), { k: 1 });
});
