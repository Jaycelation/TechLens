import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { detect } from '../engine.js';
import { lookupHash, packagesFromSources } from '../bundles.js';
import { planHunt } from '../cve.js';
import { collectBundles } from '../collector.js';

// SHA-256 of https://code.jquery.com/jquery-3.4.1.min.js (same bytes as npm dist/jquery.min.js).
const JQUERY_341 = 'CSXorXvZcTkaix6Yvo6HppcZGetbYMGWSFlBw8HfCJo=';

test('hash database pins official release files', () => {
  assert.equal(lookupHash(JQUERY_341), 'jquery@3.4.1');
  assert.equal(lookupHash('not-a-known-hash-at-all'), null);
  const r = detect({
    bundles: [{ url: 'https://shop.test/assets/vendor.js?v=9', sha256: JQUERY_341 }],
  });
  const jq = r.find((t) => t.name === 'jQuery');
  assert.deepEqual(jq.versions, ['3.4.1']);
  assert.match(
    jq.evidence[0],
    /Bundle hash: https:\/\/shop\.test\/assets\/vendor\.js = jquery@3\.4\.1/,
  );
});

test('license banners inside bundles yield versions and name the file', () => {
  const r = detect({
    bundles: [
      {
        url: 'https://app.test/main.js',
        banners: [
          '/*! jQuery v3.5.1 | (c) JS Foundation */',
          '/*!\n  * Bootstrap v4.3.1 (https://getbootstrap.com/)',
          '/*! @license DOMPurify 2.0.17 | (c) Cure53 */',
        ],
      },
    ],
  });
  assert.deepEqual(r.find((t) => t.name === 'jQuery').versions, ['3.5.1']);
  assert.deepEqual(r.find((t) => t.name === 'Bootstrap').versions, ['4.3.1']);
  assert.deepEqual(r.find((t) => t.name === 'DOMPurify').versions, ['2.0.17']);
  assert.match(r.find((t) => t.name === 'jQuery').evidence[0], /app\.test\/main\.js/);
});

test('source map paths give versions only for pnpm and Yarn layouts', () => {
  const p = packagesFromSources([
    'webpack://app/node_modules/.pnpm/react-dom@18.2.0_react@18.2.0/node_modules/react-dom/cjs/x.js',
    'webpack://app/node_modules/.pnpm/@tanstack+query-core@5.0.0-beta.1/node_modules/x.js',
    'webpack://app/.yarn/cache/lodash-npm-4.17.20-9e5d6a4bf0-abc.zip/node_modules/lodash/lodash.js',
    'webpack://app/.yarn/cache/axios-npm-1.0.0-beta.2-0123456789-abc.zip/node_modules/axios/x.js',
    'webpack://app/node_modules/react/index.js',
  ]);
  assert.deepEqual(
    p.map((x) => x.name + '@' + x.version),
    [
      'react-dom@18.2.0',
      '@tanstack/query-core@5.0.0-beta.1',
      'lodash@4.17.20',
      'axios@1.0.0-beta.2',
    ],
  );
});

test('source map packages become huntable npm technologies after curated ones', () => {
  const r = detect({
    bundles: [
      {
        url: 'https://app.test/main.js',
        mapSources: [
          'webpack://app/.yarn/cache/lodash-npm-4.17.20-9e5d6a4bf0-abc.zip/node_modules/lodash/lodash.js',
          'webpack://app/node_modules/.pnpm/axios@0.21.0/node_modules/axios/index.js',
        ],
      },
    ],
  });
  assert.deepEqual(r.find((t) => t.name === 'Lodash').versions, ['4.17.20']);
  const axios = r.find((t) => t.name === 'npm: axios');
  assert.equal(axios.npm, 'axios');
  const plan = planHunt([axios, ...r.filter((t) => t !== axios)]);
  assert.deepEqual(
    plan.queries.map((q) => q.package),
    ['lodash', 'axios'],
  );
});

test('collectBundles hashes bytes, extracts banners and source map sources without cookies', async () => {
  const body =
    '/*! jQuery v3.5.1 | (c) JS Foundation */\n!function(){}();\n//# sourceMappingURL=app.js.map';
  const map = JSON.stringify({
    sources: ['webpack://x/node_modules/.pnpm/axios@0.21.0/node_modules/axios/a.js'],
  });
  const seen = [];
  const old = { document: globalThis.document, fetch: globalThis.fetch };
  try {
    globalThis.document = {
      querySelectorAll: () => [
        { src: 'https://app.test/js/app.js' },
        { src: 'https://app.test/js/app.js' },
        { src: 'https://app.test/missing.js' },
        { src: 'data:text/javascript,1' },
      ],
    };
    globalThis.fetch = async (url, init) => {
      seen.push([url, init.credentials]);
      const text = url.endsWith('.map') ? map : url.endsWith('app.js') ? body : null;
      if (text === null) return { ok: false, headers: new Headers() };
      return {
        ok: true,
        headers: new Headers(),
        arrayBuffer: async () => new TextEncoder().encode(text).buffer,
      };
    };
    const out = await collectBundles();
    const app = out.find((b) => b.url.endsWith('app.js'));
    assert.equal(app.sha256, createHash('sha256').update(body).digest('base64'));
    assert.ok(app.banners.some((b) => b.includes('jQuery v3.5.1')));
    assert.equal(app.mapSources.length, 1);
    assert.equal(out.find((b) => b.url.endsWith('missing.js')).error, 'unreadable');
    assert.equal(out.length, 2);
    assert.ok(seen.every(([, credentials]) => credentials === 'omit'));
    assert.ok(seen.some(([url]) => url === 'https://app.test/js/app.js.map'));
  } finally {
    Object.assign(globalThis, old);
  }
});
