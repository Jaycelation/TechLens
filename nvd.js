// CPE correlation for server-side software that OSV does not cover. Only the CPE name is sent.
export const NVD_ORIGIN = 'https://services.nvd.nist.gov/*';
// NVD files nginx under f5 since 2022; the legacy nginx:nginx CPE returns no matches.
export const CPES = Object.freeze({
  Nginx: 'f5:nginx',
  OpenResty: 'openresty:openresty',
  Apache: 'apache:http_server',
  PHP: 'php:php',
  WordPress: 'wordpress:wordpress',
  Drupal: 'drupal:drupal',
});
// Without an API key NVD allows 5 requests per 30 seconds.
const MAX_QUERIES = 4;
const VERSION = /^\d+\.\d+(?:\.\d+){0,2}$/;
// Distro packages keep the upstream version but backport fixes, so CPE matches need review.
const DISTRO =
  /\((?:debian|ubuntu|centos|red hat|rhel|fedora|amazon|alpine|suse)[^)]*\)|ubuntu|deb\d|\.el\d/i;

export function cpeName(product, version) {
  return `cpe:2.3:a:${product}:${version}:*:*:*:*:*:*:*`;
}

export function planNvd(technologies) {
  const queries = [],
    skipped = [];
  for (const t of technologies) {
    if (!Object.hasOwn(CPES, t.name)) continue;
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
    if (!VERSION.test(version)) {
      skipped.push({ technology: t.name, reason: 'Phiên bản không hợp lệ cho CPE' });
      continue;
    }
    const evidence = t.evidence || [];
    queries.push({
      technology: t.name,
      ecosystem: 'CPE',
      package: CPES[t.name],
      version,
      versionEvidence: evidence,
      backportRisk: evidence.some((e) => DISTRO.test(e)),
    });
  }
  return { queries, skipped };
}

function safeUrl(raw) {
  try {
    const u = new URL(raw);
    return /^https?:$/.test(u.protocol) ? u.href : null;
  } catch {
    return null;
  }
}

export function normalizeNvd(item, q) {
  const cve = item?.cve;
  if (!cve || typeof cve.id !== 'string' || !/^CVE-\d{4}-\d{4,}$/.test(cve.id)) return null;
  if (cve.vulnStatus === 'Rejected') return null;
  const metrics = cve.metrics || {};
  const cvss = [
    ...(metrics.cvssMetricV40 || []).map((m) => ({ type: 'CVSS_V4', ...m })),
    ...(metrics.cvssMetricV31 || []).map((m) => ({ type: 'CVSS_V3', ...m })),
    ...(metrics.cvssMetricV30 || []).map((m) => ({ type: 'CVSS_V3', ...m })),
    ...(metrics.cvssMetricV2 || []).map((m) => ({ type: 'CVSS_V2', ...m })),
  ].filter((m) => typeof m.cvssData?.vectorString === 'string');
  const primary = cvss.find((m) => m.type === 'CVSS_V3') || cvss[0];
  const marker = `:${q.package}:`;
  const fixed = new Set();
  for (const config of cve.configurations || [])
    for (const node of config.nodes || [])
      for (const match of node.cpeMatch || [])
        if (match.vulnerable && match.criteria?.includes(marker) && match.versionEndExcluding)
          fixed.add(match.versionEndExcluding);
  return {
    id: cve.id,
    cves: [cve.id],
    summary: String(cve.descriptions?.find((d) => d.lang === 'en')?.value || cve.id).slice(0, 300),
    details: String(cve.descriptions?.find((d) => d.lang === 'en')?.value || '').slice(0, 5000),
    status: q.backportRisk ? 'needs_review' : 'version_affected',
    sinkStatus: 'unverified',
    technology: q.technology,
    package: q.package,
    version: q.version,
    severity: primary?.cvssData?.baseSeverity || primary?.baseSeverity || 'UNKNOWN',
    cvss: cvss.map((m) => ({ type: m.type, vector: m.cvssData.vectorString })).slice(0, 4),
    fixedVersions: [...fixed],
    ranges: [],
    kev: !!cve.cisaExploitAdd,
    references: (cve.references || [])
      .map((r) => safeUrl(r.url))
      .filter(Boolean)
      .slice(0, 8),
    source: 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(cve.id),
    modified: cve.lastModified || null,
  };
}

export async function huntNvd(
  technologies,
  { fetchFn = fetch, cache = null, force = false, onProgress = () => {}, signal } = {},
) {
  const plan = planNvd(technologies);
  const out = {
    provider: 'NVD',
    checkedAt: new Date().toISOString(),
    sinkVerified: false,
    queries: [],
    skipped: plan.skipped,
  };
  for (const q of plan.queries.slice(MAX_QUERIES))
    out.skipped.push({
      technology: q.technology,
      reason: `Giới hạn ${MAX_QUERIES} CPE mỗi lần (NVD rate limit)`,
    });
  const scheduled = plan.queries.slice(0, MAX_QUERIES);
  // Sequential on purpose: NVD rejects bursts from clients without an API key.
  for (const [i, q] of scheduled.entries()) {
    onProgress(`${q.technology} ${q.version} (NVD ${i + 1}/${scheduled.length})`);
    const key = 'cve:cpe:' + q.package + '@' + q.version;
    let raw = null,
      usedCache = false;
    try {
      if (signal?.aborted) throw new Error('Đã hủy CVE Hunt');
      if (!force && cache) {
        try {
          const c = (await cache.get(key))[key];
          const age = Date.now() - c?.at;
          if (age >= 0 && age < 6 * 3600 * 1000 && Array.isArray(c?.payload?.items)) {
            raw = c.payload;
            usedCache = true;
          }
        } catch {
          /* A failed cache read must not prevent a fresh query. */
        }
      }
      if (!raw) {
        const controller = new AbortController();
        const cancel = () => controller.abort();
        signal?.addEventListener('abort', cancel, { once: true });
        const timer = setTimeout(cancel, 30000);
        try {
          const url = new URL('https://services.nvd.nist.gov/rest/json/cves/2.0');
          url.searchParams.set('cpeName', cpeName(q.package, q.version));
          url.searchParams.set('resultsPerPage', '200');
          // isVulnerable is a valueless flag; URLSearchParams would add "=".
          const response = await fetchFn(url.href + '&isVulnerable', {
            credentials: 'omit',
            referrerPolicy: 'no-referrer',
            signal: controller.signal,
          });
          if (response.status === 403 || response.status === 429)
            throw new Error('NVD đang giới hạn tốc độ; thử lại sau 30 giây');
          if (!response.ok) throw new Error(`NVD HTTP ${response.status}`);
          const data = await response.json();
          if (!data || typeof data !== 'object' || !Array.isArray(data.vulnerabilities))
            throw new Error('NVD response không hợp lệ');
          raw = {
            items: data.vulnerabilities,
            partial: Number(data.totalResults) > data.vulnerabilities.length,
          };
        } finally {
          clearTimeout(timer);
          signal?.removeEventListener('abort', cancel);
        }
        if (cache && !raw.partial) {
          try {
            await cache.set({ [key]: { at: Date.now(), payload: raw } });
          } catch {
            /* quota: results still usable */
          }
        }
      }
      const unique = new Map();
      for (const item of raw.items) {
        const a = normalizeNvd(item, q);
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
  return out;
}
