import test from 'node:test';
import assert from 'node:assert/strict';
import { detect, RULES } from '../engine.js';
const names = (r) => r.map((t) => t.name);
test('requested stack: evidence + exact versions, no invented hosting/static export', () => {
  const snapshot = {
    scripts: [
      'https://example.org/_next/static/a.js',
      'https://code.jquery.com/jquery-4.0.0.min.js',
      'https://www.googletagmanager.com/gtag/js?id=G-AB123&secret=hidden',
      'https://www.googletagmanager.com/gtm.js?id=GTM-123',
      'https://siteimproveanalytics.com/js/siteanalyze_123.js',
      'https://example.org/_vercel/insights/script.js',
      'https://use.typekit.net/abc.css',
      'https://cdn.cookielaw.org/scripttemplates/otSDKStub.js',
      'https://example.org/turbopack/a.js',
    ],
    markers: ['radix', 'lucide', 'priority-hints'],
    meta: [{ name: 'og:title', content: 'test' }],
    css: ':root{--tw-ring-color:red}',
  };
  const r = detect(snapshot, { next: '16.2.10', react: '19.2.0' });
  for (const n of [
    'Next.js',
    'React',
    'jQuery',
    'jQuery CDN',
    'Google Analytics',
    'GA4',
    'Google Tag Manager',
    'Siteimprove',
    'Vercel Analytics',
    'Adobe Fonts',
    'OneTrust',
    'Turbopack',
    'Radix UI',
    'Lucide',
    'Priority Hints',
    'Open Graph',
    'Tailwind CSS',
  ])
    assert.ok(names(r).includes(n), n);
  assert.deepEqual(r.find((t) => t.name === 'Next.js').versions, ['16.2.10']);
  assert.deepEqual(r.find((t) => t.name === 'jQuery').versions, ['4.0.0']);
  assert.ok(!names(r).includes('Vercel'));
  assert.ok(!JSON.stringify(r).includes('hidden'));
  assert.ok(!r.find((t) => t.name === 'Next.js').categories.includes('Static site generators'));
});
test('empty and generic markup do not become technologies', () => {
  assert.deepEqual(detect(), []);
  assert.deepEqual(
    detect({
      markers: ['data-state:open'],
      css: '.flex{display:flex}',
      scripts: ['https://example.org/main.js'],
    }),
    [],
  );
  assert.ok(
    !names(detect({ scripts: ['https://www.googletagmanager.com/gtm.js?id=GTM-123'] })).includes(
      'GA4',
    ),
  );
});
test('Next resource does not expose exact version or imply React', () => {
  const r = detect({ scripts: ['https://x.test/_next/static/chunks/a.js'] });
  assert.deepEqual(r[0].versions, []);
  assert.deepEqual(names(r), ['Next.js']);
});
test('headers add hosting and correct web server category', () => {
  const r = detect({}, {}, [
    { name: 'X-Vercel-ID', value: 'abc' },
    { name: 'X-Powered-By', value: 'Next.js' },
    { name: 'Server', value: 'nginx/1.26.3' },
  ]);
  assert.ok(names(r).includes('Vercel'));
  assert.ok(r.find((t) => t.name === 'Next.js').categories.includes('Web servers'));
  assert.deepEqual(r.find((t) => t.name === 'Nginx').versions, ['1.26.3']);
});
test('version conflict preserved and evidence deduplicated', () => {
  const r = detect(
    {
      scripts: [
        'https://code.jquery.com/jquery-3.7.1.min.js',
        'https://code.jquery.com/jquery-3.7.1.min.js',
      ],
    },
    { jquery: '4.0.0' },
  );
  assert.deepEqual(r.find((t) => t.name === 'jQuery').versions, ['3.7.1', '4.0.0']);
  assert.equal(r.find((t) => t.name === 'jQuery').evidence.length, 2);
});
test('every fingerprint compiles and captures match', () => {
  for (const rule of RULES) assert.doesNotThrow(() => new RegExp(rule[3], 'i'));
  assert.ok(RULES.length >= 40);
});
test('header categories merge with existing resource evidence', () => {
  const r = detect({ scripts: ['https://x.test/_next/a.js'] }, {}, [
    { name: 'x-powered-by', value: 'Next.js' },
  ]);
  assert.ok(r[0].categories.includes('Web servers'));
});
