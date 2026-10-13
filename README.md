# TechLens 1.2 — CVE Hunt, side panel, CLI

Extension Chrome/Edge theo phong cách Wappalyzer, dùng Manifest V3. Mã nguồn và fingerprints tự viết, không sao chép cơ sở dữ liệu Wappalyzer. Extension không cần build: load trực tiếp thư mục. `npm install` chỉ cần cho test, format và CLI.

## Cài đặt

1. Clone repo (hoặc giải nén ZIP).
2. Chrome: mở `chrome://extensions`; Edge: `edge://extensions`.
3. Bật **Developer mode** → **Load unpacked**.
4. Chọn thư mục chứa `manifest.json`. Cần Chrome/Edge 123+.
5. Mở website HTTP/HTTPS, bấm icon TechLens. Ghim icon nếu cần.

## Sử dụng

- Quét theo yêu cầu, tìm kiếm theo tên/nhóm, mở bằng chứng, xuất JSON.
- **Mở side panel**: giữ kết quả khi đóng popup và tự quét lại khi chuyển tab trong cửa sổ đó. Tab chưa bấm icon TechLens cần **Cấp quyền site** để side panel đọc được.
- **Cấp quyền site (headers + quét từ side panel)**: cấp quyền tùy chọn cho origin hiện tại, sau đó tải lại website và bấm **Quét lại**. Chỉ lưu các header server, x-powered-by, x-aspnet-version, x-vercel-id, x-vercel-cache, cf-ray trong bộ nhớ phiên trình duyệt; xóa khi đóng tab.
- **Quét sâu bundle** (tắt mặc định): tải lại tối đa 25 file script của trang (thường lấy từ HTTP cache, không gửi cookie) để so hash, đọc banner license và source map. Xem phần _Phát hiện phiên bản_.
- **Lịch sử quét** (tắt mặc định): lưu 50 lần quét gần nhất trên máy (chỉ origin, tên công nghệ, phiên bản, số CVE; không lưu URL bằng chứng) và hiển thị thay đổi so với lần quét trước của cùng site. **Xóa lịch sử** xóa toàn bộ.
- Quyền activeTab/scripting đọc trang khi bấm extension; storage lưu headers tạm thời; webRequest quan sát headers khi có quyền host. Không thu cookies hay authorization. Quét công nghệ hoạt động cục bộ. CVE Hunt gửi package/phiên bản tới OSV và tên CPE tới NVD khi bạn bật.
- Thu hồi quyền site qua trang chi tiết extension của trình duyệt. Việc đọc headers vẫn có thể xảy ra trên site đã cấp quyền trong các lần truy cập tiếp theo.

## CVE Hunt

1. Sau khi quét công nghệ, bấm **CVE Hunt**, cho phép kết nối `api.osv.dev` và `services.nvd.nist.gov` khi trình duyệt hỏi (một lần).
2. Bật **Tự hunt khi quét** để tự tra cứu mỗi lần mở popup hoặc bấm Quét lại. Không quét mọi tab trong nền, không theo dõi toàn bộ lịch sử duyệt web. Tắt checkbox để ngừng auto hunt.
3. **Tra mới** bỏ cache 6 giờ và tra cứu lại. **Xuất JSON** bao gồm kết quả CVE nếu đã hunt xong.

Nguồn:

- **OSV** cho package npm: next, react, jquery, vue, nuxt, @angular/core, angular, bootstrap, chart.js, htmx.org, alpinejs, d3, lodash, moment, dompurify, cùng mọi package có phiên bản lấy từ source map (`npm: <tên>`). Không suy ra react-dom/react-server-dom-* từ React phía browser.
- **NVD** (theo CPE) cho server software: Nginx (`f5:nginx`), OpenResty, Apache HTTP Server, PHP, WordPress, Drupal. Tối đa 4 CPE mỗi lần vì NVD giới hạn 5 request/30 giây khi không có API key. Hiện cờ **CISA KEV** khi lỗ hổng đã bị khai thác thực tế.
- Header có dấu hiệu bản đóng gói distro (vd. `Apache/2.4.57 (Debian)`, `PHP/8.1.2-1ubuntu2.14`) được đánh dấu **cần review**: distro thường backport bản vá mà giữ nguyên số phiên bản.
- Plugin/theme WordPress được liệt kê kèm link WPScan; chưa tra CVE tự động vì OSV/NVD không có dữ liệu plugin đầy đủ.

- Chỉ query khi có đúng một version SemVer đầy đủ (x.y.z, có thể kèm prerelease/build). Thiếu version, version x.y, hoặc nhiều version mâu thuẫn: ghi lý do chưa kiểm tra.
- Gửi đúng package/ecosystem/version tới `/v1/query`, rồi kiểm tra lại identity npm package và dải SEMVER / danh sách affected versions. Hỗ trợ introduced, fixed (exclusive), last_affected (inclusive), limit (exclusive), prerelease, nhiều khoảng affected. Không chỉ so sánh “nhỏ hơn bản vá mới nhất”.
- **Khớp dải phiên bản**: version được công khai nằm trong khoảng affected. **Cần review**: OSV trả advisory nhưng dữ liệu range không đủ để xác nhận. Bản đã vá không khớp, advisory withdrawn được loại.
- Mọi kết quả giữ **sink chưa xác minh**. Đọc version không chứng minh code/path đang hoạt động hay input đi tới sink. Với Next.js, phải kiểm tra backend, router/config/feature và điều kiện trong advisory; với jQuery, phải chứng minh nguồn dữ liệu không tin cậy tới DOM manipulation sink đúng điều kiện CVE. Extension không tự gửi payload khai thác.
- Hiện CVE ID (nếu có alias), severity từ advisory, CVSS vector nếu có, dải affected, bản vá các nhánh, mô tả điều kiện, link nguồn và bằng chứng nhận diện version. Advisory chưa có CVE vẫn hiện GHSA/OSV ID. Fixed versions là dữ liệu các nhánh, không tự chọn bản nâng cấp cho deployment.
- Không gửi URL website, HTML, resource URLs, cookies hoặc bằng chứng version tới OSV/NVD; chỉ package/version (OSV) hoặc tên CPE (NVD). Export giữ bằng chứng locally. OSV có thể thấy IP của người gọi theo kết nối bình thường.
- Cache theo package/version hoặc CPE trong storage.session, TTL 6 giờ, không chứa domain target; preference autoHunt lưu local. Quyền OSV có thể thu hồi trong trang quản lý extension.
- Giới hạn 12 package, 3 trang API, 100 advisory/package, timeout 25 giây/request. Vượt giới hạn ghi partial hoặc skipped; lỗi mạng không biến thành kết quả “an toàn”. Không tìm thấy CVE không chứng minh không có lỗ hổng.
- Đóng popup dừng phiên quét; dùng side panel nếu muốn giữ kết quả. Kiểm tra một snapshot trang tại thời điểm scan; nếu trang navigate sau đó, quét lại để dùng version mới.

## Nhận diện và giới hạn

73 fingerprint trong `rules/*.json` (tài nguyên, DOM, CSS, meta, headers, banner) + globals. Bao gồm Next.js, React, jQuery, GA4, GTM, Siteimprove, Vercel Analytics, Adobe Fonts, Lucide, Radix UI, Tailwind, OneTrust, Open Graph, Turbopack và Priority Hints.

- Không hardcode Next.js 16.2.10 hay jQuery 4.0.0 từ ví dụ. Phiên bản chỉ xuất hiện nếu global, meta generator, tên resource, header công khai hoặc quét sâu cung cấp giá trị.
- Next.js không tự động chứng minh static export, Vercel hosting, hoặc loại web server. Chỉ gắn nhóm Web servers khi header x-powered-by xác nhận Next.js. GA4 và Google Analytics cùng hiển thị khi có tín hiệu tương ứng.
- Dấu hiệu medium là heuristic (Tailwind CSS, Turbopack, Svelte...); high cũng có thể bị website giả mạo. Đây là fingerprinting, không xác minh lỗ hổng/CVE.
- Chỉ đọc main frame; không kiểm tra iframe. Chỉ tải lại script khi bật quét sâu; không tải stylesheet. CSS khác origin thường không đọc được; bundled libraries có thể không lộ tên hoặc version.
- Giới hạn 20.000 DOM elements, 2.000 tài nguyên, 300 KB CSS để tránh quét trang quá lớn. Trang đang tải, consent/adblock và lazy loading có thể làm thiếu kết quả. Đợi trang tải rồi Quét lại.
- Header chỉ thu từ những lần điều hướng sau khi cấp quyền; cache/memory cache và service worker có thể khiến trình duyệt không phát sự kiện headers. Cache được đối chiếu URL nhưng không chứng minh độ mới tuyệt đối; tải lại nếu cần.
- Export chỉ giữ origin và bằng chứng URL đã bỏ query/hash, tránh đưa tracking tokens vào JSON. Inline chỉ xuất marker đã khớp.

## Phát hiện phiên bản (quét sâu)

Phần lớn site hiện đại bundle thư viện nên không lộ global hay URL CDN. Khi bật **Quét sâu bundle**, mỗi script được phân tích theo ba cách độc lập:

1. **Hash**: SHA-256 của file được so với `data/hashes.json`, gồm 2.531 file dist chính thức của 12 thư viện, lấy từ metadata của jsDelivr. Khớp nghĩa là đúng bản phát hành đó, dù file bị đổi tên (`vendor.js`). Hash trùng giữa nhiều phiên bản bị loại. Cập nhật bằng `node scripts/build-hashes.mjs`. Chỉ chạy trên HTTPS (cần `crypto.subtle`).
2. **Banner**: comment `/*!` và `@license` được giữ lại khi minify (`rules/banners.json`).
3. **Source map**: đường dẫn pnpm (`node_modules/.pnpm/axios@0.21.0/…`) và Yarn Berry (`.yarn/cache/lodash-npm-4.17.20-…`) có phiên bản chính xác. Đường dẫn `node_modules/<tên>/` thường thì không có, nên bị bỏ qua.

## Thêm công nghệ

Thêm rule vào file phù hợp trong `rules/`:

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

- `source`: `urls`, `markers`, `meta`, `inline`, `css`, `headers` (kèm `"header": "server"`) hoặc `banners`.
- `version`: số thứ tự capture group chứa phiên bản (tùy chọn). `showValue`: hiện giá trị header trong bằng chứng.
- `examples` là bắt buộc: `tests/rules.test.js` chạy mọi ví dụ `match` (kèm `version` nếu có) và `noMatch` cho từng rule.

Muốn thêm global, bổ sung whitelist trong `collectGlobals` và mapping trong engine. Reload extension sau khi sửa.

## CLI quét hàng loạt

Dùng cùng collector và engine với extension, chạy trên Chromium headless. **Chỉ quét các mục tiêu bạn được phép kiểm thử** (scope bug bounty, site của bạn).

```sh
npm install && npx playwright install chromium
node cli/techscan.mjs example.com https://shop.test
node cli/techscan.mjs -i domains.txt --deep --cve -o results.jsonl
node cli/techscan.mjs -i domains.txt -f csv > stack.csv
```

- Kết quả ghi dạng JSONL (mỗi site một dòng, cùng cấu trúc với **Xuất JSON**) hoặc CSV (mỗi công nghệ một dòng, kèm CVE ID).
- Request tới NVD được giãn cách trên toàn bộ lượt chạy. Cache CVE dùng chung giữa các site.
- Site lỗi (DNS, timeout) thành một dòng lỗi, không dừng cả lượt chạy.

## Kiểm thử

```sh
npm test          # unit test (Node 20+)
npm run lint      # Prettier
npm run e2e       # load extension trong Chromium thật, quét fixture cục bộ (cần Playwright + internet)
node tests/live-osv.mjs; node tests/live-nvd.mjs   # smoke test với API thật
```

CI (GitHub Actions) chạy lint + unit test trên Node 20/22 và e2e.
Mở `tests/fixture.html` qua HTTP (ví dụ `python3 -m http.server 8080` tại thư mục techlens) rồi vào `http://localhost:8080/tests/fixture.html` để kiểm thử thủ công globals/DOM. Fixture dùng dấu vết tổng hợp, không tải tracker thật.

Integration trực tiếp OSV xác nhận jQuery 3.4.1 khớp CVE-2020-11022/11023, còn 3.5.0 và 4.0.0 không khớp. NVD xác nhận nginx 1.24.0 khớp CVE-2023-44487 (KEV). Test e2e chạy collector/engine qua `chrome.scripting` trong Chromium thật. Riêng việc bấm mở side panel và các hộp thoại cấp quyền chưa tự động hóa được; cần kiểm tra tay trước khi phát hành lên store.

## Kiến trúc

```
popup.js (popup + side panel)
  ├─ collector.js   collectPage / collectGlobals / collectBundles (chạy trong tab)
  ├─ engine.js      rules/*.json + bundles.js (hash, banner, source map) → technologies
  ├─ hunt.js        cve.js (OSV, npm) + nvd.js (NVD, CPE)
  └─ history.js     lịch sử quét + diff
background.js       whitelist response headers khi có quyền site
cli/techscan.mjs    Playwright + cùng collector/engine/hunt
```

`engine.js`, `cve.js`, `nvd.js`, `hunt.js`, `history.js` là code thuần, không phụ thuộc DOM hay API trình duyệt, nên chạy được cả trong Node. Không có backend riêng, remote code hay eval.

Tài liệu API: https://developer.chrome.com/docs/extensions/reference/api/scripting và https://developer.chrome.com/docs/extensions/reference/api/webRequest

OSV API: https://google.github.io/osv.dev/post-v1-query/
NVD API: https://nvd.nist.gov/developers/vulnerabilities
OSV schema: https://ossf.github.io/osv-schema/
Ví dụ điều kiện source/sink của jQuery: https://github.com/jquery/jquery/security/advisories/GHSA-gxr4-xjj5-5px2
