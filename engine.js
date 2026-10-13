import { PACKAGES, compareVersions } from './cve.js';
import { RULES } from './rules/index.js';
import { analyzeBundles } from './bundles.js';
export { RULES };
// Fingerprints are indicators, not vulnerability assessments.
// Banner rules run per bundle in bundles.js so evidence can name the file.
const compiled = RULES.filter((rule) => rule.source !== 'banners').map((rule) => ({
  ...rule,
  re: new RegExp(rule.pattern, 'i'),
}));
const categoriesOf = (name) => RULES.find((r) => r.name === name)?.categories;

export function redact(s) {
  try {
    const u = new URL(s, 'https://relative.invalid/');
    return (
      /^https?:$/.test(u.protocol)
        ? (u.origin === 'https://relative.invalid' ? '' : u.origin) + u.pathname
        : '[non-HTTP resource]'
    ).slice(0, 240);
  } catch {
    return '[invalid resource URL]';
  }
}

// Returns the evidence string and captured version when `rule` matches `input`, else null.
export function matchRule(rule, input) {
  const re = rule.re || new RegExp(rule.pattern, 'i');
  if (rule.source === 'headers') {
    if (input.name.toLowerCase() !== rule.header) return null;
    const value = input.value || '';
    const match = re.exec(value);
    if (!match) return null;
    return {
      evidence:
        'Response header: ' + rule.header + (rule.showValue ? ' = ' + value.slice(0, 100) : ''),
      version: rule.version ? match[rule.version] : undefined,
    };
  }
  const match = re.exec(input);
  if (!match) return null;
  return {
    evidence:
      rule.source === 'urls'
        ? 'Resource: ' + redact(input)
        : rule.source === 'inline'
          ? 'Inline marker: ' + match[0].slice(0, 100)
          : rule.source + ': ' + match[0].slice(0, 100),
    version: rule.version ? match[rule.version] : undefined,
  };
}

export function detect(snapshot = {}, globals = {}, headers = []) {
  const map = new Map();
  const add = (name, categories, confidence, evidence, version, extra) => {
    if (!map.has(name))
      map.set(name, { name, categories: [...categories], confidence, versions: [], evidence: [] });
    const t = map.get(name);
    t.categories = [...new Set([...t.categories, ...categories])];
    if (confidence === 'high') t.confidence = 'high';
    if (
      version &&
      /^\d+(?:\.\d+){1,3}(?:[-+][\w.-]+)?$/.test(version) &&
      !t.versions.includes(version)
    )
      t.versions.push(version);
    if (!t.evidence.includes(evidence) && t.evidence.length < 8) t.evidence.push(evidence);
    if (extra) Object.assign(t, extra);
  };
  const sources = {
    urls: [...(snapshot.scripts || []), ...(snapshot.links || []), ...(snapshot.resources || [])],
    markers: snapshot.markers || [],
    meta: (snapshot.meta || []).map((m) => m.name + ':' + m.content),
    inline: snapshot.inline || [],
    css: [snapshot.css || ''],
    headers: headers.filter((h) => typeof h?.name === 'string'),
  };
  for (const rule of compiled)
    for (const input of sources[rule.source]) {
      const hit = matchRule(rule, input);
      if (hit) add(rule.name, rule.categories, rule.confidence, hit.evidence, hit.version);
    }
  // Extract only full versions from known package CDN layouts.
  const cdnNames = {
    jquery: 'jQuery',
    bootstrap: 'Bootstrap',
    vue: 'Vue.js',
    react: 'React',
    d3: 'D3.js',
    'Chart.js': 'Chart.js',
    htmx: 'HTMX',
    alpinejs: 'Alpine.js',
  };
  for (const raw of sources.urls) {
    let url;
    try {
      url = new URL(raw);
    } catch {
      continue;
    }
    if (!/^https?:$/.test(url.protocol)) continue;
    let name, version;
    if (url.hostname === 'cdn.jsdelivr.net' || url.hostname === 'unpkg.com') {
      const path =
        url.hostname === 'cdn.jsdelivr.net'
          ? url.pathname.startsWith('/npm/')
            ? url.pathname.slice(5)
            : ''
          : url.pathname.slice(1);
      const m = /^((?:@[^/]+\/)?[^/@]+)@([^/]+)\//.exec(path + '/');
      if (m) {
        name = Object.keys(PACKAGES).find((n) => PACKAGES[n] === m[1]);
        version = m[2];
      }
    } else if (url.hostname === 'cdnjs.cloudflare.com') {
      const m = /^\/ajax\/libs\/([^/]+)\/([^/]+)\//.exec(url.pathname);
      if (m) {
        name = Object.hasOwn(cdnNames, m[1]) ? cdnNames[m[1]] : null;
        version = m[2];
      }
    }
    // Self-hosted bootstrap-<version>.min.js filenames; compareVersions rejects non-SemVer.
    if (!name) {
      const m = /^bootstrap-(.+?)(?:\.min)?\.(?:css|js)$/.exec(url.pathname.split('/').pop());
      if (m) {
        name = 'Bootstrap';
        version = m[1];
      }
    }
    if (name && compareVersions(version, version) === 0)
      add(
        name,
        categoriesOf(name) || ['JavaScript libraries'],
        'high',
        'Package CDN: ' + redact(raw),
        version,
      );
  }
  const defs = {
    jquery: ['jQuery', ['JavaScript libraries']],
    next: ['Next.js', ['JavaScript frameworks', 'Web frameworks']],
    react: ['React', ['JavaScript libraries']],
    vue: ['Vue.js', ['JavaScript frameworks']],
    angular: ['AngularJS', ['JavaScript frameworks']],
    bootstrap: ['Bootstrap', ['UI frameworks']],
    chart: ['Chart.js', ['JavaScript libraries']],
    htmx: ['HTMX', ['JavaScript libraries']],
    alpine: ['Alpine.js', ['JavaScript frameworks']],
    d3: ['D3.js', ['JavaScript libraries']],
  };
  for (const [key, [name, cats]] of Object.entries(defs))
    if (typeof globals[key] === 'string')
      add(name, cats, 'high', 'JavaScript global: ' + key + ' version', globals[key]);
  if (globals.nextPresent)
    add(
      'Next.js',
      ['JavaScript frameworks', 'Web frameworks'],
      'high',
      'JavaScript global: next / __NEXT_DATA__',
    );
  if (globals.reactPresent)
    add('React', ['JavaScript libraries'], 'high', 'React renderer registered in devtools hook');
  if (globals.gtm)
    add('Google Tag Manager', ['Tag managers'], 'medium', 'JavaScript global: google_tag_manager');
  if (globals.onetrust)
    add('OneTrust', ['Cookie compliance'], 'high', 'JavaScript global: OneTrust');
  for (const m of snapshot.markers || [])
    if (m.startsWith('angular:'))
      add('Angular', ['JavaScript frameworks'], 'high', 'DOM: ng-version', m.slice(8));
  analyzeBundles(snapshot.bundles, add, redact);
  detectWordPressExtensions(sources.urls, map.get('WordPress')?.versions || [], add, map);
  return [...map.values()].sort((a, b) => a.name.localeCompare(b.name));
}

// WordPress enqueues assets with ?ver=, which is the plugin/theme version only when the author set
// one; otherwise WordPress fills in its own core version. Core-equal values are dropped.
const WP_PATH = /\/wp-content\/(plugins|themes)\/([a-z0-9][a-z0-9._-]{0,80})\//i;
function detectWordPressExtensions(urls, coreVersions, add, map) {
  let count = 0;
  for (const raw of urls) {
    let url;
    try {
      url = new URL(raw, 'https://relative.invalid/');
    } catch {
      continue;
    }
    const m = WP_PATH.exec(url.pathname);
    if (!m) continue;
    const kind = m[1].toLowerCase() === 'plugins' ? 'plugin' : 'theme';
    const slug = m[2].toLowerCase();
    const name = `WP ${kind}: ${slug}`;
    if (!map.has(name) && ++count > 40) continue;
    const ver = url.searchParams.get('ver');
    const version =
      ver && /^\d+\.\d+(?:\.\d+){0,2}$/.test(ver) && !coreVersions.includes(ver) ? ver : undefined;
    add(
      name,
      [kind === 'plugin' ? 'WordPress plugins' : 'WordPress themes'],
      'high',
      'Resource: ' + redact(raw) + (version ? ` (?ver=${version})` : ''),
      version,
    );
    const t = map.get(name);
    t.versionNote = 'Lấy từ ?ver= — có thể là cache-buster, cần đối chiếu readme.txt/style.css';
    t.lookup = `https://wpscan.com/${kind}/${encodeURIComponent(slug)}`;
  }
}
