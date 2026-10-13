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
test('relative and protocol-relative evidence drops secrets and URL credentials', () => {
  for (const url of [
    '/jquery-3.4.1.min.js?token=SECRET#SECRET',
    '//user:SECRET@code.jquery.com/jquery-3.4.1.min.js?token=SECRET',
  ]) {
    const r = detect({ scripts: [url] });
    assert.ok(r.some((t) => t.name === 'jQuery'));
    assert.ok(!JSON.stringify(r).includes('SECRET'));
  }
});
test('known package CDNs provide exact versions including prereleases without guessing aliases', () => {
  const r = detect({
    scripts: [
      'https://cdn.jsdelivr.net/npm/jquery@3.4.1/dist/jquery.min.js',
      'https://unpkg.com/@angular/core@17.0.0/fesm2022/core.mjs',
      'https://cdnjs.cloudflare.com/ajax/libs/vue/2.6.14/vue.min.js',
      'https://cdn.jsdelivr.net/npm/bootstrap@5.0.0-beta.1/dist/js/bootstrap.min.js',
    ],
  });
  for (const [name, v] of [
    ['jQuery', '3.4.1'],
    ['Angular', '17.0.0'],
    ['Vue.js', '2.6.14'],
    ['Bootstrap', '5.0.0-beta.1'],
  ])
    assert.deepEqual(r.find((t) => t.name === name).versions, [v]);
  for (const url of [
    'https://unpkg.com/react@latest/umd/react.js',
    'https://cdn.jsdelivr.net/npm/react@18/umd/react.js',
    'https://fake.test/npm/react@18.0.0/react.js',
  ])
    assert.ok(!detect({ scripts: [url] }).some((t) => t.versions.length));
});
test('additional library globals expose exact CVE-queryable versions', () => {
  const r = detect(
    {},
    { bootstrap: '4.3.1', chart: '2.9.4', htmx: '1.9.0', alpine: '3.0.0', d3: '5.0.0' },
  );
  assert.equal(r.length, 5);
  assert.ok(r.every((t) => t.versions.length === 1));
});
test('Bootstrap versioned filenames retain exact stable and prerelease versions', () => {
  for (const version of ['3.3.7', '5.0.0-beta.1']) {
    const r = detect({ scripts: [`https://site.test/assets/bootstrap-${version}.min.js`] });
    assert.deepEqual(r.find((t) => t.name === 'Bootstrap').versions, [version]);
  }
});
test('WordPress-bundled jQuery, core ?ver= and more CDN libraries expose versions', () => {
  const r = detect({
    scripts: [
      'https://wp.test/wp-includes/js/jquery/jquery.min.js?ver=3.7.1',
      'https://wp.test/wp-includes/js/wp-emoji-release.min.js?ver=6.4.2',
    ],
    links: [
      'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css',
      'https://cdn.jsdelivr.net/npm/@fortawesome/fontawesome-free@6.5.1/css/all.min.css',
      'https://cdnjs.cloudflare.com/ajax/libs/lodash.js/4.17.20/lodash.min.js',
    ],
  });
  const v = (name) => r.find((t) => t.name === name)?.versions;
  assert.deepEqual(v('jQuery'), ['3.7.1']);
  assert.deepEqual(v('WordPress'), ['6.4.2']);
  assert.deepEqual(v('Font Awesome'), ['4.7.0', '6.5.1']);
  assert.deepEqual(v('Lodash'), ['4.17.20']);
});
