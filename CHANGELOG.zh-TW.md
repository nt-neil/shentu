# 更新紀錄

CHANGELOG.md 的繁體中文版，網站的繁中頁讀這份。兩份的版本與日期必須一致，
每個版本都要有內容（`go test ./cmd/sitegen` 會檢查）。

## v0.2.5 (unreleased)

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
- 已知問題：分成多次執行的稽核，仍可能有少數結果和不限時間的單次執行不同；修正進行中。

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
