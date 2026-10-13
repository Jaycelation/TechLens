import { huntCves } from './cve.js';
import { huntNvd, CPES } from './nvd.js';
// Runs OSV (packages) and, when allowed, NVD (server software) and merges into one report.
export async function huntAll(technologies, { nvd = false, ...options } = {}) {
  const [osv, server] = await Promise.all([
    huntCves(technologies, options),
    nvd ? huntNvd(technologies, options) : null,
  ]);
  const queries = [
    ...osv.queries.map((q) => ({ ecosystem: 'npm', ...q })),
    ...(server?.queries || []),
  ];
  const skipped = osv.skipped.filter((s) => !Object.hasOwn(CPES, s.technology));
  if (server) skipped.push(...server.skipped);
  else
    for (const t of technologies)
      if (Object.hasOwn(CPES, t.name))
        skipped.push({ technology: t.name, reason: 'Chưa cấp quyền NVD cho server software' });
  return {
    provider: server ? 'OSV+NVD' : 'OSV',
    checkedAt: osv.checkedAt,
    sinkVerified: false,
    queries,
    skipped,
  };
}
