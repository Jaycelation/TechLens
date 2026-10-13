// Version correlation only. No exploit requests, sink claims, or target transmission.
export const PACKAGES = Object.freeze({
  'Next.js': 'next',
  React: 'react',
  jQuery: 'jquery',
  'Vue.js': 'vue',
  Nuxt: 'nuxt',
  Angular: '@angular/core',
  AngularJS: 'angular',
  Bootstrap: 'bootstrap',
  'Chart.js': 'chart.js',
  HTMX: 'htmx.org',
  'Alpine.js': 'alpinejs',
  'D3.js': 'd3',
  Lodash: 'lodash',
  'Moment.js': 'moment',
  DOMPurify: 'dompurify',
});
export const OSV_ORIGIN = 'https://api.osv.dev/*';
const EXACT =
  /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
function parse(v) {
  const m = EXACT.exec(v || '');
  if (!m) return null;
  const pre = m[4]?.split('.') || [];
  if (pre.some((x) => !x || (/^\d+$/.test(x) && x.length > 1 && x.startsWith('0')))) return null;
  return { base: m.slice(1, 4).map(BigInt), pre };
}
export function compareVersions(a, b) {
  const x = parse(a),
    y = parse(b);
  if (!x || !y) return null;
  for (let i = 0; i < 3; i++) if (x.base[i] !== y.base[i]) return x.base[i] < y.base[i] ? -1 : 1;
  if (!x.pre.length && !y.pre.length) return 0;
  if (!x.pre.length) return 1;
  if (!y.pre.length) return -1;
  for (let i = 0; i < Math.max(x.pre.length, y.pre.length); i++) {
    const p = x.pre[i],
      q = y.pre[i];
    if (p === q) continue;
    if (p === undefined) return -1;
    if (q === undefined) return 1;
    const pn = /^\d+$/.test(p),
      qn = /^\d+$/.test(q);
    if (pn && qn) return BigInt(p) < BigInt(q) ? -1 : 1;
    if (pn !== qn) return pn ? -1 : 1;
    return p < q ? -1 : 1;
  }
  return 0;
}
function rangeMatches(version, events) {
  if (!Array.isArray(events) || !events.length) return null;
  let active = false;
  let hit = false;
  for (const e of events || []) {
    if (e.introduced !== undefined) {
      const c = e.introduced === '0' ? 1 : compareVersions(version, e.introduced);
      if (c === null) return null;
      active = c >= 0;
    } else if (e.fixed !== undefined || e.limit !== undefined) {
      const c = compareVersions(version, e.fixed ?? e.limit);
      if (c === null) return null;
      hit ||= active && c < 0;
      active = false;
    } else if (e.last_affected !== undefined) {
      const c = compareVersions(version, e.last_affected);
      if (c === null) return null;
      hit ||= active && c <= 0;
      active = false;
    } else return null;
  }
  return hit || active;
}
export function matchAffected(advisory, pkg, version) {
  const affected = (advisory.affected || []).filter(
    (a) => a.package?.ecosystem === 'npm' && a.package?.name === pkg,
  );
  if (!affected.length) return 'unknown';
  let unknown = false;
  for (const a of affected) {
    if ((a.versions || []).some((v) => compareVersions(version, v) === 0)) return 'affected';
    if (!a.ranges?.length && !a.versions?.length) unknown = true;
    for (const r of a.ranges || []) {
      if (r.type !== 'SEMVER') {
        unknown = true;
        continue;
      }
      const hit = rangeMatches(version, r.events);
      if (hit === true) return 'affected';
      if (hit === null) unknown = true;
    }
  }
  return unknown ? 'unknown' : 'unaffected';
}
export function planHunt(technologies) {
  const queries = [],
    skipped = [];
  // Packages seen only in source maps (t.npm) come after curated ones so the 12-query cap
  // favours libraries with known browser exposure.
  const ordered = [...technologies].sort((a, b) => !!a.npm - !!b.npm);
  for (const t of ordered) {
    const pkg = Object.hasOwn(PACKAGES, t.name)
      ? PACKAGES[t.name]
      : typeof t.npm === 'string'
        ? t.npm
        : null;
    if (!pkg) {
      skipped.push({ technology: t.name, reason: 'Chưa có mapping package được hỗ trợ' });
      continue;
    }
    if (t.versions?.length !== 1) {
      skipped.push({
        technology: t.name,
        reason: t.versions?.length
          ? 'Có nhiều phiên bản — cần xác minh bản đang chạy'
          : 'Không có phiên bản chính xác',
      });
      continue;
    }
    const version = t.versions[0];
    if (!parse(version)) {
      skipped.push({ technology: t.name, reason: 'Phiên bản không phải SemVer đầy đủ' });
      continue;
    }
    queries.push({ technology: t.name, package: pkg, version, versionEvidence: t.evidence || [] });
  }
  return { queries, skipped };
}
function safeUrl(raw) {
  try {
    const u = new URL(raw);
    return u.protocol === 'https:' ? u.href : null;
  } catch {
    return null;
  }
}
export function normalizeAdvisory(v, q) {
  if (!v || v.withdrawn || typeof v.id !== 'string') return null;
  const status = matchAffected(v, q.package, q.version);
  if (status === 'unaffected') return null;
  const cves = [
    ...new Set([v.id, ...(v.aliases || [])].filter((s) => /^CVE-\d{4}-\d{4,}$/.test(s))),
  ];
  const applicable = (v.affected || []).filter(
    (a) => a.package?.name === q.package && a.package?.ecosystem === 'npm',
  );
  if (v.affected?.length && !applicable.length) return null;
  const fixed = [
    ...new Set(
      applicable.flatMap((a) =>
        (a.ranges || []).flatMap((r) => (r.events || []).map((e) => e.fixed).filter(Boolean)),
      ),
    ),
  ];
  return {
    id: v.id,
    cves,
    summary: String(v.summary || v.id).slice(0, 300),
    details: String(v.details || '').slice(0, 5000),
    status: status === 'affected' ? 'version_affected' : 'needs_review',
    sinkStatus: 'unverified',
    technology: q.technology,
    package: q.package,
    version: q.version,
    severity:
      v.database_specific?.severity ||
      applicable.find((a) => a.ecosystem_specific?.severity)?.ecosystem_specific.severity ||
      'UNKNOWN',
    cvss: [...(v.severity || []), ...applicable.flatMap((a) => a.severity || [])]
      .filter((s) => /^CVSS_V[234]$/.test(s.type))
      .map((s) => ({ type: s.type, vector: s.score })),
    fixedVersions: fixed,
    ranges: applicable.flatMap((a) => a.ranges || []),
    references: (v.references || [])
      .map((r) => safeUrl(r.url))
      .filter(Boolean)
      .slice(0, 8),
    source: 'https://osv.dev/vulnerability/' + encodeURIComponent(v.id),
    modified: v.modified || null,
  };
}
export async function huntCves(
  technologies,
  { fetchFn = fetch, cache = null, force = false, onProgress = () => {}, signal } = {},
) {
  const plan = planHunt(technologies);
  const out = {
    provider: 'OSV',
    checkedAt: new Date().toISOString(),
    sinkVerified: false,
    queries: [],
    skipped: plan.skipped,
  };
  for (const q of plan.queries.slice(12))
    out.skipped.push({ technology: q.technology, reason: 'Giới hạn 12 package mỗi lần' });
  const scheduled = plan.queries.slice(0, 12);
  let cursor = 0;
  async function check(q, i) {
    onProgress(`${q.technology} ${q.version} (${i + 1}/${Math.min(plan.queries.length, 12)})`);
    const key = 'cve:npm:' + q.package + '@' + q.version;
    let raw = null,
      usedCache = false;
    try {
      if (signal?.aborted) throw new Error('Đã hủy CVE Hunt');
      if (!force && cache) {
        try {
          const c = (await cache.get(key))[key];
          const age = Date.now() - c?.at;
          if (
            age >= 0 &&
            age < 6 * 3600 * 1000 &&
            Array.isArray(c?.payload?.vulns) &&
            typeof c.payload.partial === 'boolean'
          ) {
            raw = c.payload;
            usedCache = true;
          }
        } catch {
          /* A failed cache read must not prevent a fresh query. */
        }
      }
      if (!raw) {
        raw = { vulns: [], partial: false };
        let token;
        for (let page = 0; page < 3; page++) {
          if (signal?.aborted) throw new Error('Đã hủy CVE Hunt');
          const controller = new AbortController();
          const cancel = () => controller.abort();
          signal?.addEventListener('abort', cancel, { once: true });
          const timer = setTimeout(cancel, 25000);
          try {
            const response = await fetchFn('https://api.osv.dev/v1/query', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                package: { name: q.package, ecosystem: 'npm' },
                version: q.version,
                ...(token ? { page_token: token } : {}),
              }),
              credentials: 'omit',
              referrerPolicy: 'no-referrer',
              signal: controller.signal,
            });
            if (!response.ok) throw new Error(`OSV HTTP ${response.status}`);
            const data = await response.json();
            if (
              !data ||
              typeof data !== 'object' ||
              Array.isArray(data) ||
              (data.vulns !== undefined && !Array.isArray(data.vulns)) ||
              (data.next_page_token !== undefined && typeof data.next_page_token !== 'string')
            )
              throw new Error('OSV response không hợp lệ');
            raw.vulns.push(...(data.vulns || []));
            token = data.next_page_token;
            if (raw.vulns.length > 100) {
              raw.vulns = raw.vulns.slice(0, 100);
              raw.partial = true;
              break;
            }
            if (!token) break;
            if (page === 2) raw.partial = true;
          } finally {
            clearTimeout(timer);
            signal?.removeEventListener('abort', cancel);
          }
        }
        if (cache) {
          try {
            await cache.set({ [key]: { at: Date.now(), payload: raw } });
          } catch {
            /* quota: results still usable */
          }
        }
      }
      const unique = new Map();
      for (const v of raw.vulns) {
        const a = normalizeAdvisory(v, q);
        if (a && !unique.has(a.id)) unique.set(a.id, a);
      }
      out.queries[i] = {
        ...q,
        status: raw.partial ? 'partial' : 'complete',
        cached: usedCache,
        advisories: [...unique.values()],
      };
    } catch (e) {
      out.queries[i] = {
        ...q,
        status: 'error',
        error:
          e.name === 'AbortError' ? 'Hết thời gian chờ / đã hủy; chưa kiểm tra xong' : e.message,
        advisories: [],
      };
    }
  }
  // Three workers keep latency down without flooding the API; output stays ordered.
  await Promise.all(
    Array.from({ length: Math.min(3, scheduled.length) }, async () => {
      while (cursor < scheduled.length) {
        const i = cursor++;
        await check(scheduled[i], i);
      }
    }),
  );
  return out;
}
