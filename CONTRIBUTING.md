# Contributing to TechLens

## Setup

```sh
npm install
npx playwright install chromium   # only for e2e tests and the CLI
```

| Command                                              | What it runs                                                                                                    |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `npm test`                                           | Unit tests (Node 20+)                                                                                           |
| `npm run lint` / `npm run format`                    | Prettier check / fix                                                                                            |
| `npm run e2e`                                        | Loads the extension in real Chromium and scans a local fixture site (needs internet once to fetch jQuery 3.4.1) |
| `node tests/live-osv.mjs`, `node tests/live-nvd.mjs` | Smoke tests against the real OSV and NVD APIs                                                                   |

CI runs lint and unit tests on Node 20 and 22, plus e2e, for every push and pull request.

## Adding a fingerprint

Rules live in `rules/*.json` (`frameworks`, `libraries`, `analytics`, `platforms`, `headers`, `banners`). Add an object to the matching file:

```json
{
  "name": "Matomo",
  "categories": ["Analytics"],
  "source": "urls",
  "pattern": "matomo\\.js(?:[?#]|$)",
  "confidence": "high",
  "examples": {
    "match": [{ "input": "https://x.test/matomo.js" }],
    "noMatch": ["https://x.test/matomo.json"]
  }
}
```

- `source`: `urls`, `markers`, `meta` (`name:content`), `inline`, `css`, `headers` (with `"header": "server"`, lowercase) or `banners` (license comments from the deep scan).
- `pattern`: case-insensitive regular expression.
- `version` (optional): index of the capture group holding the version. `showValue` (headers only): include the header value in the evidence.
- `confidence`: `high` for unambiguous signals, `medium` for heuristics.
- `examples` is required. `tests/rules.test.js` checks every `match` example (and its `version`, if given) and every `noMatch` example.

New page globals need an entry in `collectGlobals` (`collector.js`) and in the `defs` map in `engine.js`. To make a technology eligible for CVE Hunt, map it to an npm package in `PACKAGES` (`cve.js`) or to a CPE in `CPES` (`nvd.js`).

## Version detection internals

The deep scan (`collectBundles` → `bundles.js`) uses three independent signals per script:

1. **Hash** — SHA-256 compared with `data/hashes.json`: official dist files of 12 libraries, built from jsDelivr metadata. Regenerate with `node scripts/build-hashes.mjs`; hashes shared by several versions are dropped. Requires `crypto.subtle`, so plain-HTTP pages skip it.
2. **Banner** — preserved `/*!` and `@license` comments, matched by `rules/banners.json`.
3. **Source map** — pnpm (`node_modules/.pnpm/axios@0.21.0/…`) and Yarn Berry (`.yarn/cache/lodash-npm-4.17.20-…`) paths carry exact versions. Plain `node_modules/<name>/` paths do not and are ignored. Unknown packages become `npm: <name>` technologies that CVE Hunt can query.

## CVE matching rules

- A lookup runs only when a technology has exactly one full version. Missing, partial (`x.y`) or conflicting versions are reported as skipped with the reason.
- OSV results are re-checked locally against the npm package identity and SEMVER ranges (`introduced`, `fixed`, `last_affected`, `limit`, prereleases). Data that cannot be evaluated becomes _needs review_, never "safe".
- NVD is queried by CPE with `isVulnerable`; distro-patched server versions are marked _needs review_.
- Limits: 12 OSV packages (3 in parallel, 3 pages, 100 advisories each), 4 NVD CPEs per hunt (keyless rate limit), 6-hour cache. Partial results are never cached.
- Every result keeps `sinkStatus: "unverified"`; TechLens never sends exploit payloads.

## Project layout

```
popup.js (popup + side panel)
  ├─ collector.js   collectPage / collectGlobals / collectBundles (run inside the tab)
  ├─ engine.js      rules/*.json + bundles.js (hash, banner, source map) → technologies
  ├─ hunt.js        cve.js (OSV, npm) + nvd.js (NVD, CPE)
  └─ history.js     scan history and diffs
background.js       stores whitelisted response headers when site access is granted
cli/techscan.mjs    Playwright + the same collector / engine / hunt modules
```

`engine.js`, `cve.js`, `nvd.js`, `hunt.js` and `history.js` are plain modules with no DOM or browser API dependency, so they run unchanged in Node. There is no backend, remote code or `eval`.

## Known limitations

- Only the main frame is scanned; iframes are not. Cross-origin stylesheets are usually unreadable.
- Scans are capped at 20,000 DOM elements, 2,000 resources and 300 KB of CSS. Pages still loading, consent banners and ad blockers can hide signals.
- Headers are captured only for navigations after site access is granted; cached or service-worker responses may not emit header events.
- WordPress plugin versions come from `?ver=`, which can be a cache-buster; plugins link to WPScan but are not looked up automatically.
- NVD has no usable CPE data for IIS.
