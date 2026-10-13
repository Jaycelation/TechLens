// Header observation is opt-in per origin. Keep only public technology headers.
const allowed = new Set([
  'server',
  'x-powered-by',
  'x-vercel-id',
  'x-vercel-cache',
  'cf-ray',
  'x-aspnet-version',
]);
const pending = new Map();
chrome.webRequest.onHeadersReceived.addListener(
  (d) => {
    if (d.tabId < 0 || d.type !== 'main_frame') return;
    const task = (pending.get(d.tabId) || Promise.resolve())
      .catch(() => {})
      .then(() =>
        chrome.storage.session.set({
          ['headers:' + d.tabId]: {
            url: d.url,
            observedAt: d.timeStamp,
            headers: (d.responseHeaders || [])
              .filter((h) => allowed.has(h.name.toLowerCase()))
              .map((h) => ({ name: h.name, value: (h.value || '').slice(0, 200) })),
          },
        }),
      );
    pending.set(d.tabId, task);
    task
      .finally(() => {
        if (pending.get(d.tabId) === task) pending.delete(d.tabId);
      })
      .catch(() => {});
  },
  { urls: ['http://*/*', 'https://*/*'], types: ['main_frame'] },
  ['responseHeaders'],
);
chrome.tabs.onRemoved.addListener((id) => {
  (pending.get(id) || Promise.resolve())
    .catch(() => {})
    .then(() => chrome.storage.session.remove('headers:' + id));
});
