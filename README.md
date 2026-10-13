# TechLens 1.1.2 — CVE Hunt
Extension Chrome/Edge theo phong cách Wappalyzer, dùng Manifest V3. Mã nguồn và fingerprints tự viết, không sao chép cơ sở dữ liệu Wappalyzer. Không cần npm install hoặc build.

## Thay đổi 1.1.2
- Giữ các advisory đã tải khi trang tiếp theo của OSV lỗi; hiển thị trạng thái chưa đầy đủ và nguyên nhân.
- Không cache kết quả chưa đầy đủ trong 6 giờ; lần tra tiếp theo sẽ thử lại.
- Sửa nhận diện Bootstrap trong tên file có phiên bản, gồm prerelease; không đưa `.min.js` vào phiên bản đối chiếu CVE.
- Bổ sung kiểm thử CDN, SemVer, cache, 3 truy vấn đồng thời, lỗi phân trang và tải lại cùng URL.

Bản 1.1.1 đã thêm phiên bản chính xác từ jsDelivr/unpkg/cdnjs, globals của Bootstrap/Chart.js/HTMX/Alpine.js/D3, 3 worker OSV, và đối chiếu document ID khi quét. Yêu cầu Chromium 106+.

## Cài đặt
1. Giải nén ZIP.
2. Chrome: mở `chrome://extensions`; Edge: `edge://extensions`.
3. Bật **Developer mode** → **Load unpacked**.
4. Chọn thư mục `techlens` chứa `manifest.json`.
5. Mở website HTTP/HTTPS, bấm icon TechLens. Ghim icon nếu cần.

## Sử dụng
- Quét theo yêu cầu, tìm kiếm theo tên/nhóm, mở bằng chứng, xuất JSON.
- **Bật đọc headers cho site này**: cấp quyền tùy chọn cho origin hiện tại, sau đó tự tải lại website và bấm **Quét lại**. Chỉ lưu các header công nghệ server, x-powered-by, x-vercel-id, x-vercel-cache, cf-ray trong bộ nhớ phiên trình duyệt; xóa khi đóng tab.
- Quyền activeTab/scripting đọc trang khi bấm extension; storage lưu headers tạm thời; webRequest quan sát headers khi có quyền host. Không thu cookies hay authorization. Quét công nghệ hoạt động cục bộ. CVE Hunt gửi package và phiên bản tới OSV khi bạn bật.
- Thu hồi quyền site qua trang chi tiết extension của trình duyệt. Việc đọc headers vẫn có thể xảy ra trên site đã cấp quyền trong các lần truy cập tiếp theo.

## CVE Hunt (mới ở 1.1)
1. Sau khi quét công nghệ, bấm **CVE Hunt**, cho phép kết nối `api.osv.dev` nếu trình duyệt hỏi.
2. Bật **Tự hunt khi quét** để tự tra cứu mỗi lần mở popup hoặc bấm Quét lại. Không quét mọi tab trong nền, không theo dõi toàn bộ lịch sử duyệt web. Tắt checkbox để ngừng auto hunt.
3. **Tra mới** bỏ cache 6 giờ và tra cứu lại. **Xuất JSON** bao gồm kết quả CVE nếu đã hunt xong.

Nguồn: OSV API, dữ liệu bao gồm GHSA/CVE theo package. Hiện hỗ trợ mapping npm: next, react, jquery, vue, nuxt, @angular/core, angular, bootstrap, chart.js, htmx.org, alpinejs, d3. Không tra CVE cho Analytics/PaaS hay web server Nginx/Apache trong bản này. Không suy ra react-dom/react-server-dom-* từ React phía browser.

- Chỉ query khi có đúng một version SemVer đầy đủ (x.y.z, có thể kèm prerelease/build). Thiếu version, version x.y, hoặc nhiều version mâu thuẫn: ghi lý do chưa kiểm tra.
- Gửi đúng package/ecosystem/version tới `/v1/query`, rồi kiểm tra lại identity npm package và dải SEMVER / danh sách affected versions. Hỗ trợ introduced, fixed (exclusive), last_affected (inclusive), limit (exclusive), prerelease, nhiều khoảng affected. Không chỉ so sánh “nhỏ hơn bản vá mới nhất”.
- **Khớp dải phiên bản**: version được công khai nằm trong khoảng affected. **Cần review**: OSV trả advisory nhưng dữ liệu range không đủ để xác nhận. Bản đã vá không khớp, advisory withdrawn được loại.
- Mọi kết quả giữ **sink chưa xác minh**. Đọc version không chứng minh code/path đang hoạt động hay input đi tới sink. Với Next.js, phải kiểm tra backend, router/config/feature và điều kiện trong advisory; với jQuery, phải chứng minh nguồn dữ liệu không tin cậy tới DOM manipulation sink đúng điều kiện CVE. Extension không tự gửi payload khai thác.
- Hiện CVE ID (nếu có alias), severity từ advisory, CVSS vector nếu có, dải affected, bản vá các nhánh, mô tả điều kiện, link nguồn và bằng chứng nhận diện version. Advisory chưa có CVE vẫn hiện GHSA/OSV ID. Fixed versions là dữ liệu các nhánh, không tự chọn bản nâng cấp cho deployment.
- Không gửi URL website, HTML, resource URLs, cookies hoặc bằng chứng version tới OSV; chỉ package/version và page_token khi cần. Export giữ bằng chứng locally. OSV có thể thấy IP của người gọi theo kết nối bình thường.
- Cache theo npm/package/version trong storage.session, TTL 6 giờ, không chứa domain target; preference autoHunt lưu local. Quyền OSV có thể thu hồi trong trang quản lý extension.
- Tối đa 3 package tra đồng thời. Giới hạn 12 package, 3 trang API, 100 advisory/package, timeout 25 giây/request. Vượt giới hạn ghi partial hoặc skipped; lỗi mạng không biến thành kết quả “an toàn”. Không tìm thấy CVE không chứng minh không có lỗ hổng.
- Đóng popup dừng phiên quét; mở lại để chạy lại. Kiểm tra một snapshot trang tại thời điểm scan; nếu trang navigate sau đó, quét lại để dùng version mới.

## Nhận diện và giới hạn
45 fingerprints tài nguyên/DOM/CSS + globals và headers. Bao gồm Next.js, React, jQuery, GA4, GTM, Siteimprove, Vercel Analytics, Adobe Fonts, Lucide, Radix UI, Tailwind, OneTrust, Open Graph, Turbopack và Priority Hints.

- Không hardcode Next.js 16.2.10 hay jQuery 4.0.0 từ ví dụ. Phiên bản chỉ xuất hiện nếu global, meta generator, tên resource hoặc header công khai cung cấp giá trị.
- Next.js không tự động chứng minh static export, Vercel hosting, hoặc loại web server. Chỉ gắn nhóm Web servers khi header x-powered-by xác nhận Next.js. GA4 và Google Analytics cùng hiển thị khi có tín hiệu tương ứng.
- Dấu hiệu medium là heuristic (Tailwind CSS, Turbopack, Svelte...); high cũng có thể bị website giả mạo. Đây là fingerprinting, không xác minh lỗ hổng/CVE.
- Chỉ đọc main frame; không kiểm tra iframe, không tải source bundle/stylesheet từ xa. CSS khác origin thường không đọc được; bundled libraries có thể không lộ tên hoặc version.
- Giới hạn 20.000 DOM elements, 2.000 tài nguyên, 300 KB CSS để tránh quét trang quá lớn. Trang đang tải, consent/adblock và lazy loading có thể làm thiếu kết quả. Đợi trang tải rồi Quét lại.
- Header chỉ thu từ những lần điều hướng sau khi cấp quyền; cache/memory cache và service worker có thể khiến trình duyệt không phát sự kiện headers. Cache được đối chiếu URL và thời điểm bắt đầu điều hướng của snapshot; headers từ lần tải trước không được tái sử dụng.
- Export chỉ giữ origin và bằng chứng URL đã bỏ query/hash, tránh đưa tracking tokens vào JSON. Inline chỉ xuất marker đã khớp.

## Thêm công nghệ
Sửa `engine.js` → `RULES`: `[name, categories, source, regex, confidence, versionCaptureGroup?]`.
Nguồn: urls, markers, meta, inline, css. Muốn thêm global, bổ sung whitelist trong collectGlobals và mapping trong engine. Reload extension sau sửa.

## Kiểm thử
`node --test tests/*.test.js` (Node 18+).
Mở `tests/fixture.html` qua HTTP (ví dụ `python3 -m http.server 8080` tại thư mục techlens) rồi vào `http://localhost:8080/tests/fixture.html` để kiểm thử thủ công globals/DOM. Fixture dùng dấu vết tổng hợp, không tải tracker thật.

Đã pass 36 kiểm thử tự động cho engine, collector, popup và CVE Hunt (SemVer, boundaries, prerelease, cache, API failure, pagination, stale results). Integration trực tiếp OSV xác nhận jQuery 3.4.1 khớp CVE-2020-11022/11023, còn 3.5.0 và 4.0.0 không khớp hai CVE đó. Có thể chạy lại bằng `node tests/live-osv.mjs`. Đã kiểm tra Chromium 150 headless với fixture cục bộ: nạp service worker, quét DOM/globals/headers, hiển thị popup, tra OSV và dùng lại cache. Harness cấp sẵn host permissions cho localhost/OSV và chỉ định tab fixture; chưa kiểm tra luồng hộp thoại cấp quyền hoặc Edge trực tiếp.

## Kiến trúc
popup.js điều phối → collector.js đọc DOM và global whitelist → engine.js trả kết quả có bằng chứng. background.js giữ whitelist headers khi có quyền site. Không có backend riêng, remote code, eval hay dependency cài ngoài. CVE Hunt gọi OSV API để lấy dữ liệu advisory (JSON).

Tài liệu API: https://developer.chrome.com/docs/extensions/reference/api/scripting và https://developer.chrome.com/docs/extensions/reference/api/webRequest

OSV API: https://google.github.io/osv.dev/post-v1-query/
OSV schema: https://ossf.github.io/osv-schema/
Ví dụ điều kiện source/sink của jQuery: https://github.com/jquery/jquery/security/advisories/GHSA-gxr4-xjj5-5px2
