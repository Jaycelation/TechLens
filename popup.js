import { collectPage, collectGlobals, collectBundles } from './collector.js';
import { detect } from './engine.js';
import { OSV_ORIGIN } from './cve.js';
import { NVD_ORIGIN } from './nvd.js';
import { huntAll } from './hunt.js';
import { addHistory, diffScans } from './history.js';
const $ = (id) => document.getElementById(id);
// The same page serves the popup and the side panel; the panel stays open across tab switches.
const PANEL = new URLSearchParams(location.search).has('panel');
let report = null,
  tab = null,
  origin = null,
  huntController = null,
  windowId = null,
  prefs = {};
function node(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}
function link(url, text) {
  const a = node('a', text);
  a.href = url;
  a.target = '_blank';
  a.rel = 'noopener noreferrer';
  return a;
}
function render() {
  $('results').replaceChildren();
  if (!report) return;
  const q = $('search').value.toLowerCase().trim();
  const groups = new Map();
  const visible = report.technologies.filter((t) =>
    (t.name + ' ' + t.categories.join(' ')).toLowerCase().includes(q),
  );
  $('count').textContent = `${visible.length} / ${report.technologies.length} công nghệ`;
  for (const t of visible)
    for (const category of t.categories) {
      if (!groups.has(category)) groups.set(category, []);
      groups.get(category).push(t);
    }
  for (const [cat, techs] of [...groups].sort(([a], [b]) => a.localeCompare(b))) {
    $('results').append(node('h2', cat));
    for (const t of techs) {
      const card = node('article', undefined, 'card'),
        row = node('div', undefined, 'row');
      row.append(node('span', t.name, 'name'));
      if (t.versions.length) row.append(node('span', t.versions.join(' / '), 'version'));
      row.append(
        node(
          'span',
          t.confidence === 'high' ? 'Tin cậy cao' : 'Dấu hiệu',
          `confidence ${t.confidence}`,
        ),
      );
      card.append(row);
      if (t.versions.length && t.versionNote) card.append(node('p', t.versionNote, 'note'));
      const details = node('details'),
        list = node('ul');
      details.append(node('summary', 'Xem bằng chứng'));
      for (const ev of t.evidence) list.append(node('li', ev));
      details.append(list);
      if (t.lookup) details.append(link(t.lookup, 'Tra lỗ hổng trên WPScan'));
      card.append(details);
      $('results').append(card);
    }
  }
  if (!visible.length)
    $('results').append(
      node('p', q ? 'Không có kết quả phù hợp.' : 'Chưa tìm thấy dấu vết được hỗ trợ.', 'empty'),
    );
}
function resetView() {
  huntController?.abort();
  huntController = null;
  $('hunt').disabled = true;
  $('fresh').disabled = true;
  $('hunt-results').replaceChildren();
  $('hunt-status').textContent = 'Chưa tra CVE.';
  $('count').textContent = '0 công nghệ';
  $('host').textContent = 'Trang hiện tại';
  $('notice').textContent = 'Quét công nghệ cục bộ · CVE Hunt dùng OSV/NVD khi bật';
  $('scan').disabled = true;
  $('export').disabled = true;
  $('headers').disabled = true;
  origin = null;
  tab = null;
  report = null;
  $('results').replaceChildren();
  $('status').textContent = 'Đang đọc dấu vết công nghệ…';
}
async function scan() {
  resetView();
  try {
    [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!Number.isInteger(tab?.id) || !/^https?:\/\//.test(tab.url || ''))
      throw new Error(
        'Hãy mở một trang HTTP/HTTPS. Trang hệ thống và Chrome Web Store không cho phép quét.',
      );
    origin = new URL(tab.url).origin;
    const target = { tabId: tab.id };
    $('host').textContent = new URL(tab.url).host;
    if (prefs.deepScan)
      $('status').textContent = 'Đang đọc dấu vết và tải lại script để phân tích…';
    const [page, global, bundles] = await Promise.all([
      chrome.scripting.executeScript({ target, func: collectPage }),
      chrome.scripting.executeScript({ target, world: 'MAIN', func: collectGlobals }),
      prefs.deepScan ? chrome.scripting.executeScript({ target, func: collectBundles }) : null,
    ]);
    // Document IDs distinguish reloads even when the URL does not change.
    const documentId = page[0]?.documentId;
    if (
      !page[0]?.result ||
      !global[0]?.result ||
      !documentId ||
      documentId !== global[0]?.documentId ||
      (bundles && bundles[0]?.documentId !== documentId)
    )
      throw new Error('Trang đã tải lại khi quét. Bấm Quét lại.');
    const [check] = await chrome.scripting.executeScript({ target, func: () => location.href });
    const current = await chrome.tabs.get(tab.id);
    if (
      check?.documentId !== documentId ||
      check?.result !== tab.url ||
      current.url !== tab.url ||
      current.status === 'loading'
    )
      throw new Error('Trang đã chuyển hướng. Bấm Quét lại.');
    const key = 'headers:' + tab.id;
    const cache = (await chrome.storage.session.get(key))[key];
    const sameDocument = !!(
      cache &&
      typeof cache.url === 'string' &&
      Array.isArray(cache.headers) &&
      cache.url.split('#')[0] === tab.url.split('#')[0] &&
      Number.isFinite(page[0].result.navigationStartedAt) &&
      cache.observedAt >= page[0].result.navigationStartedAt
    );
    const headers = sameDocument ? cache.headers : [];
    const bundleList = Array.isArray(bundles?.[0]?.result) ? bundles[0].result : null;
    report = {
      site: origin,
      scannedAt: new Date().toISOString(),
      headersAvailable: !!sameDocument,
      deepScan: bundleList
        ? {
            scripts: bundleList.length,
            unreadable: bundleList.filter((b) => b.error).length,
            hashed: bundleList.filter((b) => b.sha256).length,
          }
        : null,
      technologies: detect(
        { ...page[0].result, bundles: bundleList || [] },
        global[0].result,
        headers,
      ),
    };
    const parts = [
      `${report.technologies.length} công nghệ`,
      sameDocument ? 'Có response headers' : 'DOM, JavaScript và resources',
    ];
    if (report.deepScan)
      parts.push(
        `quét sâu ${report.deepScan.scripts - report.deepScan.unreadable}/${report.deepScan.scripts} script`,
      );
    $('status').textContent = parts.join(' · ');
    $('export').disabled = false;
    $('hunt').disabled = false;
    $('fresh').disabled = false;
    render();
    await saveHistory(report);
    const permitted = await chrome.permissions.contains({ origins: [origin + '/*'] });
    $('headers').disabled = permitted;
    $('headers').textContent = permitted
      ? 'Đã cấp quyền site — tải lại trang nếu cần headers'
      : 'Cấp quyền site (headers + quét từ side panel)';
    if (prefs.autoHunt && (await chrome.permissions.contains({ origins: [OSV_ORIGIN] })))
      void runHunt(false);
  } catch (e) {
    const denied = /cannot access|permission/i.test(e.message || '');
    $('status').textContent = denied
      ? 'Chưa có quyền đọc tab này. Bấm icon TechLens trên tab, hoặc cấp quyền site bên dưới.'
      : e.message || 'Không thể quét trang.';
    if (denied && origin) {
      $('headers').disabled = false;
      $('headers').textContent = 'Cấp quyền site (headers + quét từ side panel)';
    }
  } finally {
    $('scan').disabled = false;
  }
}
$('scan').addEventListener('click', scan);
$('search').addEventListener('input', render);
$('headers').addEventListener('click', async () => {
  if (!origin) return;
  try {
    const granted = await chrome.permissions.request({ origins: [origin + '/*'] });
    if (granted) {
      $('headers').disabled = true;
      $('headers').textContent = 'Đã cấp quyền cho site này';
      $('notice').textContent = 'Tải lại trang rồi bấm Quét lại để lấy headers.';
    }
  } catch (e) {
    $('notice').textContent = e.message;
  }
});
$('export').addEventListener('click', () => {
  if (!report) return;
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'techlens-' + new URL(report.site).hostname + '.json';
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
function renderHunt(data) {
  $('hunt-results').replaceChildren();
  let matches = 0,
    review = 0,
    errors = 0,
    partial = 0,
    kev = 0;
  for (const q of data.queries) {
    const cpe = q.ecosystem === 'CPE';
    const section = node('div', undefined, 'finding');
    section.append(
      node('strong', `${q.technology} ${q.version} · ${cpe ? 'cpe' : 'npm'}/${q.package}`),
    );
    const proof = node('details');
    proof.append(node('summary', 'Bằng chứng nhận diện phiên bản'));
    const evidence = node('ul');
    for (const ev of q.versionEvidence || []) evidence.append(node('li', ev));
    proof.append(evidence);
    section.append(proof);
    if (q.backportRisk)
      section.append(
        node(
          'p',
          'Bản đóng gói của distro: bản vá có thể đã được backport dù số phiên bản cũ. Cần kiểm tra changelog gói.',
          'review',
        ),
      );
    if (q.status === 'error') {
      errors++;
      section.append(node('p', `Chưa kiểm tra: ${q.error}`));
    } else {
      if (q.status === 'partial') {
        partial++;
        section.append(node('p', 'Kết quả chưa đầy đủ; có thể còn advisory chưa tải.'));
      }
      if (q.warning) section.append(node('p', q.warning));
      section.append(
        node('p', `${q.cached ? 'Cache ≤ 6 giờ · ' : ''}${q.advisories.length} advisory liên quan`),
      );
      if (!q.advisories.length)
        section.append(
          node(
            'p',
            `Không tìm thấy trong dữ liệu ${cpe ? 'NVD' : 'OSV'} đã kiểm tra. Không phải chứng nhận an toàn.`,
          ),
        );
      for (const a of q.advisories) {
        if (a.status === 'version_affected') matches++;
        else review++;
        if (a.kev) kev++;
        const item = node('details');
        item.append(
          node('summary', `${a.cves.join(', ') || a.id} · ${a.severity}${a.kev ? ' · KEV' : ''}`),
        );
        item.append(node('p', a.summary));
        if (a.kev)
          item.append(node('p', 'CISA KEV: lỗ hổng này đã bị khai thác thực tế.', 'review'));
        item.append(
          node(
            'p',
            a.status === 'version_affected'
              ? cpe
                ? 'NVD khớp CPE theo phiên bản · sink chưa xác minh'
                : 'Khớp dải phiên bản · sink chưa xác minh'
              : cpe
                ? 'Ứng viên từ NVD · cần kiểm tra bản vá của distro'
                : 'Ứng viên từ OSV · cần kiểm tra dải phiên bản',
            'review',
          ),
        );
        item.append(
          node(
            'p',
            `Bản vá theo advisory (các nhánh): ${a.fixedVersions.join(', ') || 'Chưa công bố trong dữ liệu'}`,
          ),
        );
        if (a.ranges.length)
          item.append(node('pre', JSON.stringify(a.ranges, null, 2), 'advisory-details'));
        if (a.cvss.length) item.append(node('p', a.cvss.map((s) => s.vector).join(' / ')));
        item.append(node('p', a.details, 'advisory-details'));
        item.append(link(a.source, cpe ? 'Mở trên NVD' : 'Mở advisory trên OSV'));
        const refs = node('ul');
        for (const u of a.references) {
          const li = node('li');
          li.append(link(u, u));
          refs.append(li);
        }
        item.append(refs);
        item.append(
          node(
            'p',
            'Xác minh tiếp: version trên backend → điều kiện trong advisory → input tới sink → impact có thể tái hiện.',
          ),
        );
        section.append(item);
      }
    }
    $('hunt-results').append(section);
  }
  const d = node('details');
  d.append(node('summary', `${data.skipped.length} công nghệ chưa kiểm tra`));
  const ul = node('ul');
  for (const s of data.skipped) ul.append(node('li', `${s.technology}: ${s.reason}`));
  d.append(ul);
  $('hunt-results').append(d);
  $('hunt-status').textContent =
    `${matches} khớp phiên bản · ${review} cần review · ${errors} lỗi${kev ? ' · ' + kev + ' KEV' : ''}${partial ? ' · ' + partial + ' kết quả chưa đầy đủ' : ''}. Chưa xác minh sink/khả năng khai thác.`;
}
async function runHunt(force) {
  if (!report) return;
  const owner = report;
  huntController?.abort();
  const controller = new AbortController();
  huntController = controller;
  $('hunt').disabled = true;
  $('fresh').disabled = true;
  $('hunt-status').textContent = 'Đang tra OSV/NVD…';
  try {
    const nvd = await chrome.permissions.contains({ origins: [NVD_ORIGIN] });
    const data = await huntAll(owner.technologies, {
      nvd,
      cache: chrome.storage.session,
      force,
      signal: controller.signal,
      onProgress: (t) => {
        if (report === owner && !controller.signal.aborted)
          $('hunt-status').textContent = 'Đang tra: ' + t;
      },
    });
    if (report !== owner || controller.signal.aborted) return;
    owner.cveHunt = data;
    renderHunt(data);
    await saveHistory(owner);
  } catch (e) {
    if (report === owner && !controller.signal.aborted)
      $('hunt-status').textContent = 'Chưa kiểm tra: ' + e.message;
  } finally {
    if (report === owner && huntController === controller) {
      $('hunt').disabled = false;
      $('fresh').disabled = false;
      huntController = null;
    }
  }
}
async function manualHunt(force) {
  const owner = report;
  if (!owner) return;
  try {
    // One prompt covers both providers; neither receives the website URL.
    const granted = await chrome.permissions.request({ origins: [OSV_ORIGIN, NVD_ORIGIN] });
    if (report !== owner) return;
    if (granted) await runHunt(force);
    else $('hunt-status').textContent = 'Chưa cấp quyền OSV/NVD; chưa tra CVE.';
  } catch (e) {
    $('hunt-status').textContent = e.message;
  }
}
$('hunt').addEventListener('click', () => manualHunt(false));
$('fresh').addEventListener('click', () => manualHunt(true));
$('auto-hunt').addEventListener('change', async () => {
  const enabled = $('auto-hunt').checked;
  try {
    if (enabled && !(await chrome.permissions.request({ origins: [OSV_ORIGIN, NVD_ORIGIN] }))) {
      $('auto-hunt').checked = false;
      return;
    }
    prefs.autoHunt = enabled;
    await chrome.storage.local.set({ autoHunt: enabled });
    if (enabled) await runHunt(false);
  } catch (e) {
    $('auto-hunt').checked = false;
    $('hunt-status').textContent = e.message;
  }
});
$('deep-scan').addEventListener('change', async () => {
  prefs.deepScan = $('deep-scan').checked;
  await chrome.storage.local.set({ deepScan: prefs.deepScan });
  if (prefs.deepScan) await scan();
});

// Scan history is opt-in because it records which sites were visited.
async function saveHistory(entry) {
  if (!prefs.saveHistory) return;
  const { history = [] } = await chrome.storage.local.get('history');
  const next = addHistory(history, entry);
  await chrome.storage.local.set({ history: next });
  renderHistory(next);
}
function renderHistory(history) {
  $('history-list').replaceChildren();
  $('history-summary').textContent = `Lịch sử quét (${history.length})`;
  for (const [i, h] of history.entries()) {
    const li = node('li');
    const when = new Date(h.scannedAt).toLocaleString();
    li.append(node('strong', new URL(h.site).host));
    li.append(node('span', ` · ${when} · ${h.technologies.length} công nghệ`));
    if (h.cve)
      li.append(
        node('span', ` · ${h.cve.matches} khớp CVE${h.cve.kev ? ', ' + h.cve.kev + ' KEV' : ''}`),
      );
    const previous = history.slice(i + 1).find((p) => p.site === h.site);
    if (previous) {
      const d = diffScans(previous, h);
      const changes = [
        ...d.added.map((n) => '+ ' + n),
        ...d.removed.map((n) => '− ' + n),
        ...d.changed.map((c) => `~ ${c.name} ${c.from || '?'} → ${c.to || '?'}`),
      ];
      if (changes.length) li.append(node('p', 'So với lần trước: ' + changes.join(', '), 'note'));
    }
    $('history-list').append(li);
  }
}
$('save-history').addEventListener('change', async () => {
  prefs.saveHistory = $('save-history').checked;
  await chrome.storage.local.set({ saveHistory: prefs.saveHistory });
  if (prefs.saveHistory && report) await saveHistory(report);
});
$('clear-history').addEventListener('click', async () => {
  await chrome.storage.local.remove?.('history');
  renderHistory([]);
});

$('open-panel').addEventListener('click', () => {
  // sidePanel.open must run synchronously inside the click to keep the user gesture.
  chrome.sidePanel.setOptions({ path: 'popup.html?panel', enabled: true });
  chrome.sidePanel.open({ windowId }).then(
    () => window.close(),
    (e) => {
      $('notice').textContent = e.message;
    },
  );
});

async function init() {
  if (PANEL) document.body.classList.add('panel');
  $('open-panel').hidden = PANEL || !chrome.sidePanel?.open;
  windowId = (await chrome.windows?.getCurrent?.())?.id ?? null;
  prefs = await chrome.storage.local.get(['autoHunt', 'deepScan', 'saveHistory', 'history']);
  $('auto-hunt').checked = !!prefs.autoHunt;
  $('deep-scan').checked = !!prefs.deepScan;
  $('save-history').checked = !!prefs.saveHistory;
  renderHistory(Array.isArray(prefs.history) ? prefs.history : []);
  if (PANEL) {
    // Follow the active tab in this window so results stay visible while browsing.
    let timer;
    const rescan = () => {
      clearTimeout(timer);
      timer = setTimeout(scan, 300);
    };
    chrome.tabs.onActivated.addListener((info) => info.windowId === windowId && rescan());
    chrome.tabs.onUpdated.addListener(
      (id, info, t) =>
        t.active && t.windowId === windowId && info.status === 'complete' && rescan(),
    );
  }
  await scan();
}
init();
