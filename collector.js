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
