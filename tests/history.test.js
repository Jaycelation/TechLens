import test from 'node:test';
import assert from 'node:assert/strict';
import { addHistory, diffScans, MAX_HISTORY } from '../history.js';

const report = (scannedAt, techs, cveHunt) => ({
  site: 'https://a.test',
  scannedAt,
  technologies: techs.map(([name, ...versions]) => ({
    name,
    versions,
    evidence: ['Resource: secret'],
  })),
  cveHunt,
});

test('history keeps newest first, replaces a re-saved scan and caps size', () => {
  let h = addHistory([], report('t1', [['jQuery', '3.4.1']]));
  h = addHistory(h, report('t2', [['jQuery', '3.5.0']]));
  const hunted = report('t2', [['jQuery', '3.5.0']], {
    provider: 'OSV',
    queries: [
      { advisories: [{ status: 'version_affected', kev: true }, { status: 'needs_review' }] },
    ],
  });
  h = addHistory(h, hunted);
  assert.deepEqual(
    h.map((e) => e.scannedAt),
    ['t2', 't1'],
  );
  assert.deepEqual(h[0].cve, { provider: 'OSV', matches: 1, review: 1, kev: 1 });
  assert.ok(!JSON.stringify(h).includes('secret'));
  for (let i = 0; i < MAX_HISTORY + 5; i++) h = addHistory(h, report('x' + i, []));
  assert.equal(h.length, MAX_HISTORY);
});

test('diff reports added, removed and version changes', () => {
  const d = diffScans(
    report('t1', [['jQuery', '3.4.1'], ['Hotjar']]),
    report('t2', [['jQuery', '3.5.0'], ['Sentry']]),
  );
  assert.deepEqual(d, {
    added: ['Sentry'],
    removed: ['Hotjar'],
    changed: [{ name: 'jQuery', from: '3.4.1', to: '3.5.0' }],
  });
});
