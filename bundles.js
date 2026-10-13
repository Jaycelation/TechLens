// Version evidence from script bodies collected by the opt-in deep scan (collectBundles).
// Three independent signals: exact file hash, preserved license banners, source map paths.
import HASHES from './data/hashes.json' with { type: 'json' };
import { PACKAGES } from './cve.js';
import { RULES } from './rules/index.js';

export const HASH_LENGTH = 16;
const BANNERS = RULES.filter((r) => r.source === 'banners').map((r) => ({
  ...r,
  re: new RegExp(r.pattern, 'i'),
}));
const NAME_BY_PACKAGE = Object.fromEntries(
  Object.entries(PACKAGES).map(([name, pkg]) => [pkg, name]),
);
const CATEGORY_BY_NAME = Object.fromEntries(RULES.map((r) => [r.name, r.categories]));
const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const MAX_MAP_PACKAGES = 40;

export function lookupHash(sha256) {
  return typeof sha256 === 'string' ? HASHES[sha256.slice(0, HASH_LENGTH)] || null : null;
}

// pnpm and Yarn Berry encode the installed version in the path; plain node_modules does not.
export function packagesFromSources(sources) {
  const found = new Map();
  for (const source of sources || []) {
    if (typeof source !== 'string') continue;
    let m = /node_modules\/\.pnpm\/((?:@[^+/]+\+)?[^@/]+)@(\d+\.\d+\.\d+[^_/]*)/.exec(source);
    let name, version;
    if (m) {
      name = m[1].replace('+', '/');
      version = m[2];
    } else if (
      (m =
        /\.yarn\/(?:cache|unplugged)\/([a-z0-9][\w.-]*?)-npm-(\d+\.\d+\.\d+(?:-[\w.]+?)?)-[0-9a-f]{10}-/.exec(
          source,
        ))
    ) {
      name = m[1];
      version = m[2];
    } else continue;
    if (!VERSION.test(version)) continue;
    const key = name + '@' + version;
    if (!found.has(key)) found.set(key, { name, version, path: source.slice(0, 200) });
  }
  return [...found.values()];
}

export function analyzeBundles(bundles, add, redact) {
  let mapPackages = 0;
  for (const bundle of bundles || []) {
    if (!bundle || typeof bundle.url !== 'string') continue;
    const where = redact(bundle.url);
    const hit = lookupHash(bundle.sha256);
    if (hit) {
      const at = hit.lastIndexOf('@');
      const pkg = hit.slice(0, at);
      const name = NAME_BY_PACKAGE[pkg] || pkg;
      add(
        name,
        CATEGORY_BY_NAME[name] || ['JavaScript libraries'],
        'high',
        `Bundle hash: ${where} = ${hit} (SHA-256 khớp bản phát hành chính thức)`,
        hit.slice(at + 1),
      );
    }
    for (const banner of (bundle.banners || []).slice(0, 50)) {
      if (typeof banner !== 'string') continue;
      for (const rule of BANNERS) {
        const m = rule.re.exec(banner);
        if (m)
          add(
            rule.name,
            rule.categories,
            rule.confidence,
            `Bundle banner: ${where} → ${m[0].replace(/\s+/g, ' ').slice(0, 80)}`,
            m[rule.version],
          );
      }
    }
    for (const p of packagesFromSources(bundle.mapSources)) {
      const known = NAME_BY_PACKAGE[p.name];
      if (!known && mapPackages >= MAX_MAP_PACKAGES) continue;
      const name = known || 'npm: ' + p.name;
      if (!known) mapPackages++;
      add(
        name,
        known ? CATEGORY_BY_NAME[known] || ['JavaScript libraries'] : ['npm packages'],
        'high',
        `Source map: ${where} → ${p.path}`,
        p.version,
        known ? undefined : { npm: p.name },
      );
    }
  }
}
