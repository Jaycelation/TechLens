// Optional integration smoke test. Sends only a public CPE name to NVD.
// Run manually: node tests/live-nvd.mjs (requires internet, not part of npm test).
import assert from 'node:assert/strict';
import { huntNvd } from '../nvd.js';
const result = await huntNvd([
  { name: 'Nginx', versions: ['1.24.0'], evidence: ['Integration fixture; not a target website'] },
]);
const q = result.queries[0];
assert.equal(q.status, 'complete', JSON.stringify(q));
assert.ok(q.advisories.some((a) => a.id === 'CVE-2023-44487' && a.kev));
console.log(`nginx 1.24.0: ${q.advisories.length} CVE, CVE-2023-44487 (KEV) present`);
