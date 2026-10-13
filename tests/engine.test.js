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
test('fingerprint set stays broad', () => {
  assert.ok(RULES.length >= 40);
});
test('header categories merge with existing resource evidence', () => {
  const r = detect({ scripts: ['https://x.test/_next/a.js'] }, {}, [
    { name: 'x-powered-by', value: 'Next.js' },
  ]);
  assert.ok(r[0].categories.includes('Web servers'));
});
test('WordPress plugins and themes are listed with ?ver= only when it differs from core', () => {
  const r = detect({
    meta: [{ name: 'generator', content: 'WordPress 6.4.2' }],
    scripts: [
      'https://wp.test/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.8.4',
      'https://wp.test/wp-content/plugins/akismet/_inc/akismet.js?ver=6.4.2',
      '/wp-content/themes/twentytwentyfour/style.css?ver=1.0&token=SECRET',
    ],
  });
  assert.deepEqual(r.find((t) => t.name === 'WordPress').versions, ['6.4.2']);
  const cf7 = r.find((t) => t.name === 'WP plugin: contact-form-7');
  assert.deepEqual(cf7.versions, ['5.8.4']);
  assert.ok(cf7.categories.includes('WordPress plugins'));
  assert.equal(cf7.lookup, 'https://wpscan.com/plugin/contact-form-7');
  assert.deepEqual(r.find((t) => t.name === 'WP plugin: akismet').versions, []);
  assert.deepEqual(r.find((t) => t.name === 'WP theme: twentytwentyfour').versions, ['1.0']);
  assert.ok(!JSON.stringify(r).includes('SECRET'));
});
test('server headers expose CPE-ready versions', () => {
  const r = detect({}, {}, [
    { name: 'Server', value: 'Apache/2.4.57 (Debian)' },
    { name: 'X-Powered-By', value: 'PHP/8.1.2-1ubuntu2.14' },
  ]);
  assert.deepEqual(r.find((t) => t.name === 'Apache').versions, ['2.4.57']);
  assert.deepEqual(r.find((t) => t.name === 'PHP').versions, ['8.1.2']);
  assert.match(r.find((t) => t.name === 'PHP').evidence[0], /ubuntu/);
});
