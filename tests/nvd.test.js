import test from 'node:test';
import assert from 'node:assert/strict';
import { planNvd, normalizeNvd, huntNvd, cpeName } from '../nvd.js';
import { huntAll } from '../hunt.js';

const item = (id = 'CVE-2023-44487', extra = {}) => ({
  cve: {
    id,
    vulnStatus: 'Analyzed',
    descriptions: [{ lang: 'en', value: 'HTTP/2 rapid reset' }],
    metrics: {
      cvssMetricV31: [
        {
          cvssData: {
            vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
            baseSeverity: 'HIGH',
          },
        },
      ],
    },
    configurations: [
      {
        nodes: [
          {
            cpeMatch: [
              {
                vulnerable: true,
                criteria: 'cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*',
                versionEndExcluding: '1.25.3',
              },
              {
                vulnerable: true,
                criteria: 'cpe:2.3:a:other:x:*:*:*:*:*:*:*:*',
                versionEndExcluding: '9.9.9',
              },
            ],
          },
        ],
      },
    ],
    cisaExploitAdd: '2023-10-10',
    references: [{ url: 'javascript:alert(1)' }, { url: 'https://example.org/a' }],
    ...extra,
  },
});
const nginx = {
  name: 'Nginx',
  versions: ['1.24.0'],
  evidence: ['Response header: server = nginx/1.24.0'],
};
const response = (data, status = 200) => ({ ok: status < 400, status, json: async () => data });

test('plan maps known server software to CPE and skips ambiguous versions', () => {
  const p = planNvd([
    nginx,
    { name: 'Apache', versions: [] },
    { name: 'PHP', versions: ['8.1.2', '7.4.33'] },
    { name: 'jQuery', versions: ['3.4.1'] },
  ]);
  assert.deepEqual(
    p.queries.map((q) => q.package),
    ['f5:nginx'],
  );
  assert.equal(p.skipped.length, 2);
  assert.equal(cpeName('f5:nginx', '1.24.0'), 'cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*');
});

test('distro builds are marked for review because fixes may be backported', () => {
  const [q] = planNvd([
    {
      name: 'PHP',
      versions: ['8.1.2'],
      evidence: ['Response header: x-powered-by = PHP/8.1.2-1ubuntu2.14'],
    },
  ]).queries;
  assert.equal(q.backportRisk, true);
  assert.equal(normalizeNvd(item(), q).status, 'needs_review');
});

test('normalize keeps CVSS, KEV, fixed versions for the queried product and safe links', () => {
  const [q] = planNvd([nginx]).queries;
  const a = normalizeNvd(item(), q);
  assert.equal(a.status, 'version_affected');
  assert.equal(a.severity, 'HIGH');
  assert.equal(a.kev, true);
  assert.deepEqual(a.fixedVersions, ['1.25.3']);
  assert.deepEqual(a.references, ['https://example.org/a']);
  assert.equal(normalizeNvd(item('CVE-2020-1', { vulnStatus: 'Rejected' }), q), null);
  assert.equal(normalizeNvd({ cve: { id: 'not-a-cve' } }, q), null);
});

test('hunt sends only the CPE name, caches, and reports rate limiting as an error', async () => {
  const urls = [];
  const state = {};
  const cache = {
    get: async (k) => ({ [k]: state[k] }),
    set: async (d) => Object.assign(state, d),
  };
  const fetchFn = async (url, init) => {
    urls.push(url);
    assert.equal(init.credentials, 'omit');
    return response({ totalResults: 1, vulnerabilities: [item()] });
  };
  const first = await huntNvd([nginx], { fetchFn, cache });
  assert.equal(first.queries[0].advisories.length, 1);
  assert.match(urls[0], /cpeName=cpe%3A2\.3%3Aa%3Af5%3Anginx%3A1\.24\.0/);
  assert.match(urls[0], /&isVulnerable$/);
  assert.ok(!urls[0].includes('example'));
  const second = await huntNvd([nginx], { fetchFn, cache });
  assert.equal(second.queries[0].cached, true);
  assert.equal(urls.length, 1);
  const limited = await huntNvd([nginx], { fetchFn: async () => response({}, 429), force: true });
  assert.equal(limited.queries[0].status, 'error');
  assert.match(limited.queries[0].error, /giới hạn tốc độ/);
});

test('huntAll merges OSV and NVD and explains when NVD is not allowed', async () => {
  const fetchFn = async (url) =>
    String(url).includes('nvd')
      ? response({ totalResults: 1, vulnerabilities: [item()] })
      : response({ vulns: [] });
  const techs = [nginx, { name: 'jQuery', versions: ['4.0.0'], evidence: [] }];
  const both = await huntAll(techs, { fetchFn, nvd: true });
  assert.equal(both.provider, 'OSV+NVD');
  assert.deepEqual(
    both.queries.map((q) => q.ecosystem),
    ['npm', 'CPE'],
  );
  assert.ok(!both.skipped.some((s) => s.technology === 'Nginx'));
  const osvOnly = await huntAll(techs, { fetchFn });
  assert.equal(osvOnly.queries.length, 1);
  assert.match(osvOnly.skipped.find((s) => s.technology === 'Nginx').reason, /NVD/);
});
