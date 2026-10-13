// Executed in the isolated world. No network calls or cookie collection.
export function collectPage() {
  const take = (selector, attr) =>
    Array.from(document.querySelectorAll(selector))
      .slice(0, 2000)
      .map((e) => e[attr] || e.getAttribute(attr) || '');
  const scripts = take('script[src]', 'src');
  const links = take('link[href]', 'href');
  const resources = performance
    .getEntriesByType('resource')
    .slice(-2000)
    .map((e) => e.name);
  const meta = Array.from(document.querySelectorAll('meta'))
    .slice(0, 300)
    .map((e) => ({ name: e.name || e.getAttribute('property') || '', content: e.content || '' }));
  const inline = Array.from(document.scripts)
    .filter((s) => !s.src)
    .slice(0, 100)
    .map((s) => (s.textContent || '').slice(0, 20000));
  const markers = new Set();
  const elements = Array.from(document.querySelectorAll('*')).slice(0, 20000);
  for (const el of elements) {
    for (const a of Array.from(el.attributes)) {
      if (a.name.startsWith('data-radix-') || (a.name === 'id' && a.value.startsWith('radix-')))
        markers.add('radix');
      if (a.name.startsWith('data-v-')) markers.add('vue-scoped');
      if (a.name.startsWith('data-react')) markers.add('react');
    }
    if (el.classList?.contains('lucide')) markers.add('lucide');
    if (el.hasAttribute('fetchpriority') && /^(high|low)$/.test(el.getAttribute('fetchpriority')))
      markers.add('priority-hints');
    if (el.hasAttribute('ng-version')) markers.add('angular:' + el.getAttribute('ng-version'));
  }
  let css = '';
  for (const sheet of Array.from(document.styleSheets).slice(0, 50)) {
    try {
      for (const rule of Array.from(sheet.cssRules).slice(0, 1000)) {
        css += rule.cssText.slice(0, 1000) + '\n';
        if (css.length > 300000) break;
      }
    } catch {}
    if (css.length > 300000) break;
  }
  return {
    scripts,
    links,
    resources,
    meta,
    inline,
    markers: [...markers],
    css,
    navigationStartedAt: performance.timeOrigin,
  };
}
// Read a small whitelist of page globals; never return tokens or page data.
export function collectGlobals() {
  const out = {};
  const read = (key, fn) => {
    try {
      const v = fn();
      if (typeof v === 'string' || typeof v === 'boolean')
        out[key] = typeof v === 'string' ? v.slice(0, 80) : v;
    } catch {}
  };
  read('jquery', () => window.jQuery?.fn?.jquery);
  read('next', () => window.next?.version);
  read('nextPresent', () => !!window.__NEXT_DATA__ || !!window.next);
  read('react', () => window.React?.version);
  read('reactPresent', () => !!window.__REACT_DEVTOOLS_GLOBAL_HOOK__?.renderers?.size);
  read('vue', () => window.Vue?.version);
  read('angular', () => window.angular?.version?.full);
  read('bootstrap', () => window.bootstrap?.Tooltip?.VERSION);
  read('chart', () => window.Chart?.version);
  read('htmx', () => window.htmx?.version);
  read('alpine', () => window.Alpine?.version);
  read('d3', () => window.d3?.version);
  read('gtm', () => !!window.google_tag_manager);
  read('onetrust', () => !!window.OneTrust);
  read('wordpress', () => !!window.wp?.hooks);
  return out;
}
// Opt-in deep scan: re-reads script files (normally from the HTTP cache) to hash them and pull
// license banners and source map paths. Runs in the isolated world; cookies are not sent.
export async function collectBundles(limits = {}) {
  const maxScripts = limits.maxScripts || 40;
  const maxBytes = limits.maxBytes || 4_000_000;
  const maxMapBytes = limits.maxMapBytes || 8_000_000;
  // Module bundlers load libraries as imported chunks that never appear as <script src>,
  // so also take every JS file the page fetched, largest first (vendor chunks are big).
  const loaded = performance
    .getEntriesByType('resource')
    .filter((e) => e.initiatorType === 'script' || /\.m?js(?:[?#]|$)/.test(e.name))
    .sort((a, b) => (b.decodedBodySize || 0) - (a.decodedBodySize || 0))
    .map((e) => e.name);
  const urls = [
    ...new Set(
      [
        ...Array.from(document.querySelectorAll('script[src]')).map((s) => s.src),
        ...Array.from(document.querySelectorAll('link[rel="modulepreload"][href]')).map(
          (l) => l.href,
        ),
        ...loaded,
      ].filter((u) => /^https?:/.test(u)),
    ),
  ].slice(0, maxScripts);
  const read = async (url, limit) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 15000);
    try {
      const response = await fetch(url, {
        credentials: 'omit',
        cache: 'force-cache',
        signal: controller.signal,
      });
      if (!response.ok) return null;
      if (Number(response.headers.get('content-length')) > limit) return null;
      const buffer = await response.arrayBuffer();
      return buffer.byteLength > limit ? null : buffer;
    } catch {
      return null;
    } finally {
      clearTimeout(timer);
    }
  };
  const base64 = (buffer) => {
    const bytes = new Uint8Array(buffer);
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  };
  const banners = (text) => {
    const out = [text.slice(0, 300)];
    const re = /\/\*[!*][\s\S]{0,600}?\*\/|(?:^|\n)\/\/! [^\n]*(?:\n\/\/! [^\n]*){0,3}/g;
    let m;
    while ((m = re.exec(text)) && out.length < 50)
      if (m[0].startsWith('/*!') || /@license|@preserve|\/\/!/.test(m[0]))
        out.push(m[0].slice(0, 300));
    return out;
  };
  const mapSources = async (text, scriptUrl) => {
    const m = /\/\/[#@] sourceMappingURL=([^\s'"]+)\s*$/.exec(text.slice(-1000));
    if (!m) return null;
    let json;
    if (m[1].startsWith('data:')) {
      const inline = /^data:application\/json[^,]*;base64,(.+)$/.exec(m[1]);
      if (!inline || inline[1].length > maxMapBytes) return null;
      json = atob(inline[1]);
    } else {
      let url;
      try {
        url = new URL(m[1], scriptUrl);
      } catch {
        return null;
      }
      if (!/^https?:$/.test(url.protocol)) return null;
      const buffer = await read(url.href, maxMapBytes);
      if (!buffer) return null;
      json = new TextDecoder().decode(buffer);
    }
    try {
      const map = JSON.parse(json);
      const sources = [
        ...(map.sources || []),
        ...(map.sections || []).flatMap((s) => s.map?.sources || []),
      ];
      return sources
        .filter((s) => typeof s === 'string')
        .slice(0, 3000)
        .map((s) => s.slice(0, 300));
    } catch {
      return null;
    }
  };
  const out = [];
  let cursor = 0;
  async function worker() {
    while (cursor < urls.length) {
      const url = urls[cursor++];
      const buffer = await read(url, maxBytes);
      if (!buffer) {
        out.push({ url, error: 'unreadable' });
        continue;
      }
      const text = new TextDecoder().decode(buffer);
      // crypto.subtle only exists on HTTPS pages; hashing is skipped elsewhere.
      const sha256 = globalThis.crypto?.subtle
        ? base64(await crypto.subtle.digest('SHA-256', buffer))
        : null;
      out.push({
        url,
        size: buffer.byteLength,
        sha256,
        banners: banners(text),
        mapSources: await mapSources(text, url),
      });
    }
  }
  await Promise.all(Array.from({ length: Math.min(4, urls.length) }, worker));
  return out;
}
