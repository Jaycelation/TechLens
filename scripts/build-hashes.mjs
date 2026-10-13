// Builds data/hashes.json: truncated SHA-256 of official dist files -> "package@version".
// Uses jsDelivr's metadata API, which reports file hashes without downloading the files.
// Run: node scripts/build-hashes.mjs   (network required; takes a few minutes)
import fs from 'node:fs';

const FILES = {
  jquery: /^\/dist\/jquery(?:\.slim)?(?:\.min)?\.js$/,
  bootstrap: /^\/dist\/js\/bootstrap(?:\.bundle)?(?:\.min)?\.js$/,
  vue: /^\/dist\/vue(?:\.global)?(?:\.prod)?(?:\.min)?\.js$/,
  angular: /^\/angular(?:\.min)?\.js$/,
  react: /^\/umd\/react\.(?:production\.min|development)\.js$/,
  d3: /^\/(?:dist\/)?d3(?:\.min)?\.js$/,
  'chart.js': /^\/dist\/[Cc]hart(?:\.umd)?(?:\.min)?\.js$/,
  'htmx.org': /^\/dist\/htmx(?:\.min)?\.js$/,
  alpinejs: /^\/dist\/cdn(?:\.min)?\.js$/,
  lodash: /^\/lodash(?:\.min)?\.js$/,
  moment: /^\/(?:min\/)?moment(?:\.min)?\.js$/,
  dompurify: /^\/dist\/purify(?:\.min)?\.js$/,
};
export const HASH_LENGTH = 16;
const API = 'https://data.jsdelivr.com/v1/packages/npm/';

async function json(url, tries = 3) {
  for (let i = 0; ; i++) {
    const r = await fetch(url);
    if (r.ok) return r.json();
    if (i >= tries || r.status === 404) throw new Error(`${r.status} ${url}`);
    await new Promise((res) => setTimeout(res, 1000 * (i + 1)));
  }
}

const jobs = [];
for (const [pkg, pattern] of Object.entries(FILES)) {
  const { versions } = await json(API + pkg);
  for (const { version } of versions)
    if (/^\d+\.\d+\.\d+$/.test(version)) jobs.push({ pkg, version, pattern });
}
console.error(`${jobs.length} package versions`);

const out = {};
const collisions = new Set();
let done = 0;
async function worker() {
  while (jobs.length) {
    const { pkg, version, pattern } = jobs.pop();
    try {
      const { files } = await json(`${API}${pkg}@${version}?structure=flat`);
      for (const f of files)
        if (pattern.test(f.name)) {
          const key = f.hash.slice(0, HASH_LENGTH);
          const value = `${pkg}@${version}`;
          if (out[key] && out[key] !== value) collisions.add(key);
          else out[key] = value;
        }
    } catch (e) {
      console.error(`skip ${pkg}@${version}: ${e.message}`);
    }
    if (++done % 200 === 0) console.error(`${done} done`);
  }
}
await Promise.all(Array.from({ length: 8 }, worker));
// A file shared by several versions cannot pin a version, so drop it.
for (const key of collisions) delete out[key];
const sorted = Object.fromEntries(Object.entries(out).sort(([a], [b]) => a.localeCompare(b)));
fs.writeFileSync(new URL('../data/hashes.json', import.meta.url), JSON.stringify(sorted) + '\n');
console.error(`${Object.keys(sorted).length} hashes, ${collisions.size} ambiguous dropped`);
