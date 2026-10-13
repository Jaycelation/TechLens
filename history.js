// Compact, local-only scan history. Stores technology names/versions, never evidence URLs.
export const MAX_HISTORY = 50;

export function summarize(report) {
  const advisories = (report.cveHunt?.queries || []).flatMap((q) => q.advisories || []);
  return {
    site: report.site,
    scannedAt: report.scannedAt,
    technologies: report.technologies.map((t) => ({ name: t.name, versions: [...t.versions] })),
    cve: report.cveHunt
      ? {
          provider: report.cveHunt.provider,
          matches: advisories.filter((a) => a.status === 'version_affected').length,
          review: advisories.filter((a) => a.status !== 'version_affected').length,
          kev: advisories.filter((a) => a.kev).length,
        }
      : null,
  };
}

// Newest first. Re-saving the same scan (e.g. after CVE Hunt) replaces it instead of duplicating.
export function addHistory(history, report) {
  const entry = summarize(report);
  const rest = (Array.isArray(history) ? history : []).filter(
    (h) => !(h.site === entry.site && h.scannedAt === entry.scannedAt),
  );
  return [entry, ...rest].slice(0, MAX_HISTORY);
}

export function diffScans(previous, current) {
  const before = new Map(previous.technologies.map((t) => [t.name, t.versions.join(' / ')]));
  const after = new Map(current.technologies.map((t) => [t.name, t.versions.join(' / ')]));
  return {
    added: [...after.keys()].filter((n) => !before.has(n)),
    removed: [...before.keys()].filter((n) => !after.has(n)),
    changed: [...after]
      .filter(([n, v]) => before.has(n) && before.get(n) !== v)
      .map(([name, to]) => ({ name, from: before.get(name), to })),
  };
}
