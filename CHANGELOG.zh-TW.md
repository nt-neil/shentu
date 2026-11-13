# 更新紀錄

CHANGELOG.md 的繁體中文版，網站的繁中頁讀這份。兩份的版本與日期必須一致，
每個版本都要有內容（`go test ./cmd/sitegen` 會檢查）。

## v0.3.0 (unreleased)

- SSH 登入沒成功的紀錄改為先讀 journald：ssh 與 sshd 單元的標記由 journald 自己填入，本機用戶不能偽造。
  journald 不存在、讀取時間到了上限（60 s），或沒有 sshd 紀錄時，才改讀文字紀錄檔（`auth.log`、`secure`）。
  本機任何人都能用 `logger` 寫入一行 sshd 紀錄，所以這時 `auth_events` 標為 partial，
  原因是新的 `unverified_source`，多次試圖登入的告警也會附註來源未驗證。
  不是 root 的用戶沒有權限看系統紀錄時，不再當成「沒有登入沒成功」。
- Amazon Linux 2 與 2023：套件漏洞改用 Amazon 的 ALAS 公告比對（讀每個套件庫的 `updateinfo`，
  先用 `repomd.xml` 裡的 sha256 驗證再暫存起來），Amazon Linux 2 的 extras 也算在內。
  已經不再有更新的 Amazon Linux 1 回報「說不出有沒有漏洞」。真的在 Amazon Linux 2023 的 VM 上錄製過；
  Amazon Linux 2 只有測試測到。
- Alpine Linux：從 apk 資料庫讀套件（OSV 比對），讀 OpenRC 服務與 runlevel，
  並把 `/etc/local.d`、busybox crond（`/etc/crontabs`、`/etc/periodic`）與 `/etc/inittab` 列為開機或定時自動執行的位置；
  busybox syslog 只讀 auth 類的 sshd 紀錄，並標為未驗證。真的在 Alpine 3.22 的 VM 上
  以 root 與用戶分別錄製過一次。
- SUSE：openSUSE Leap、Tumbleweed，以及 SLES、SLED、SLES for SAP
  （SLE 15 每個模組查一個 OSV ecosystem；OSV 沒有收錄的會列為沒有查）。
  Leap 用自製的測試資料驗證，SLES 還沒有在真的主機上試過。
- 每日報告會列出沒查成或只查了一部分的漏洞檢查；套件清單讀出 0 個時回報「說不出有沒有漏洞」，
  不再當成「沒有漏洞」。
- 程式碼稽核的資料夾寫成 `/var/www/html/`（最後多一個 `/`）或 `/` 時，接續上次的位置稽核
  不會再把整個資料夾跳過。資料夾改為先整理成標準寫法，所以更新版本後的第一次稽核找不到上次的位置，
  會從開始完整檢查一次。

## v0.2.5 — 2026-11-13

- `app_code_audit` 會跨檔追蹤呼叫：在一個檔案讀進來、在另一個檔案的危險呼叫用掉的輸入，
  會在危險呼叫處報出，並標明來源檔案。
- 框架路由模型：WordPress 的 hook、shortcode 與 REST 路由，Laravel 路由、Django URL、
  Flask 與 FastAPI 的 view，以及 Express handler 的參數都視為輸入，路由註冊在別的檔案也一樣。
- 新的規則類別：LDAP 注入、NoSQL 運算子注入、危險的檔案上傳、弱加密與寫死的憑證；
  TypeScript 檔案用 JavaScript 規則檢查。
- 稽核結果會在多次執行之間保留，大型應用程式分幾次巡邏就能掃完，不必一次跑完。
- 稽核依伺服器調整自己：記憶體上限取 min(1 GiB、可用記憶體的 25%、服務 cgroup 的 50%)，
  並行數依 CPU 數與系統負載決定。
- 誤報更少：`wp_send_json` 的輸出、`JSON_HEX_TAG` 的資料區塊、不是 collection 的物件上的
  MongoDB 查詢，以及 Django 的 `_meta.get_field` 檢查。

### 已知問題

- 分成多次執行的稽核，仍可能有少數結果和不限時間的單次執行不同；修正進行中。
- `php-deserialization-phar-wrapper` 會把 WordPress REST attachments controller 裡對上傳暫存路徑做的
  `filesize()` 報出來，這是誤報：那個路徑是 PHP 自己產生的，但引擎還分不出上傳檔的 `tmp_name`
  和客戶端填的 `name`。
- js-nosqli-mongo-query 會把 SQL 資料庫上的 TypeORM repository 呼叫當成 MongoDB 查詢，也就是 options
  的 where 由請求值組成的 find/findOne（例如 n8n 的公開 API 和查 credential 的地方）。TypeORM 會把
  這些值當成 SQL 參數，所以這些是誤報；v0.2.6 會改用能認出 TypeORM 的 receiver 檢查來區分。
- `js-cmdi-spawn-shell` 在指令和參數都固定、只有 options（例如 `cwd` 或 `env`）帶到請求值時，
  `spawn()` 和 `execFile()` 仍然會被報出。
- js-xss-response 不再對 Server-Sent Events 例外：在 text/event-stream 的 handler 裡寫
  res.write("data: " + 值) 會被報成 XSS（誤報），但不會因為 SSE 而漏報；依 handler 的
  Content-Type 分辨串流的功能排在 v0.2.6。
- `->get_settings()` 在任何 class 裡都會被當成 Elementor widget 的輸入，所以 `WP_Widget::get_settings()`
  和 WooCommerce `WC_Settings_Page::get_settings()` 回傳的值（由管理員存入）也會被報出來。要把來源
  限定在繼承 `\Elementor\Widget_Base` 的 class，引擎得支援依 class 限定 source，預定 v0.2.6。
  經由 ->get_settings() 讀到的值，也可能被追進 WordPress 後台的欄位定義，以及少數已經有防護的
  SQL 位置（例如先用 isset() 檢查，或在 ORDER BY FIELD() 裡用 $wpdb->prepare() 綁定），因此在這些
  地方會多出誤報。v0.2.6 會把這個來源限縮到 Elementor 元件。
- 在 `$wpdb->prepare()`／`->prepare()` 的格式字串裡，如果佔位符清單是由只回傳常數的 callback 產生
  （例如 `implode(',', array_map(fn($v) => '%d', $ids))`，或改用 `function ($v) { return '%d'; }` 的寫法），
  只要 `$ids` 來自請求，仍然會被當成輸入報出來。
  `array_fill(0, count($ids), '%d')` 和 `sizeof()` 的寫法已能辨識。要讀出 callback 的回傳值需要
  改引擎，預定 v0.2.6。
- `python-path-traversal-send-file` 會把 `zipfile.ZipFile(request.files[...])` 報出來，這是誤報：它開的是
  上傳的檔案串流，不是路徑。要在同一個參數裡分出請求的檔案串流和客戶端填寫的 filename，需要改引擎，預定 v0.2.6。

## v0.2.4 — 2026-11-09

- 規則改用專屬格式並在 CI 檢查，起始共 33 條規則。
- `accounts_audit` 會報出共用的 SSH 金鑰、`ld.so.preload`，以及不屬於任何套件的 PAM 模組。
- `processes` 會標出挖礦程式。
- 巡邏時每個 webshell 報一行。

## v0.2.3 — 2026-11-09

- `app_code_audit`：離線稽核網站應用程式自己的檔案。

## v0.2.2 — 2026-11-08

- `package_vulns` 對每個遭積極利用的 CVE 只報一次。

## v0.2.1 — 2026-11-08

- `shentu bot`：從 Telegram 和 Shentu 對話，配對有防護，權限分四個等級範圍。
- 用量追蹤，以及可選的每月 AI 預算。
- 第二輪模型比較：14 個模型、11 個情境。

## v0.2.0 — 2026-11-07

- 一個指令從安裝到運作：引導式設定。
- 站點盤點與應用程式相依套件掃描。

## v0.1.1 — 2026-11-07

- `package_vulns` 會標出遭積極利用的漏洞（CISA KEV）。
- Slack 與 Discord webhook。
- 每次發布前跑安全不變式測試、提示注入測試組與 govulncheck。

## v0.1.0 — 2026-11-07

- 首次發布：Linux 伺服器用的 `shentu chat` 與 `shentu patrol`，以及設定本機模型或 API 金鑰的
  `shentu setup`。
