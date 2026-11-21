# 更新紀錄

CHANGELOG.md 的繁體中文版，網站的繁中頁讀這份。兩份的版本與日期必須一致，
每個版本都要有內容（`go test ./cmd/sitegen` 會檢查）。

## v0.5.4 (unreleased)

- 建議按鈕按下後，如果 bot 在檢查過程中或等待確認時被停止，log 會記成 bot 已停止（#166），不再記成被拒絕或操作者沒有確認。

## v0.5.3 (unreleased)

- 建議按鈕按下後一定會有回覆（#163）：會先立刻回覆「正在重新檢查這個位址」，檢查之前先在 log 記下這次按下
  （`proposal_press`），重新檢查最多一分鐘，超過時間就用閘門的固定字詞拒絕；過程中出錯也會回覆並記錄。
  和以前一樣，按鈕按下後就算用掉了：因為檢查超過時間、出錯或被重啟中斷而被拒的按鈕不能再按，請改用下一次調查的按鈕。
- Telegram 的封鎖只詢問閘門會放行的位址（#155、#158）：從聊天管道執行 block_ip 時，會在要求按 ✅ 之前先跑一次 #108 閘門的檢查。閘門會拒絕的位址立刻被拒，不會出現 ✅；agent 只會收到閘門的固定字詞（和位址），閘門的原始訊息只留在伺服器的紀錄裡；確認之後封鎖本身失敗時，錯誤內容也只留在紀錄裡。確認過的封鎖在執行時照舊會再檢查一次。
- bot 等待時（#156、#158）：等待期間傳來的訊息，回覆會說明正在等什麼（上面的 ✅、驗證器的密碼，或伺服器以 `sudo shentu bot approve` 核准），不再回「上一個問題還在處理中」；等待期間傳來的問題不會交給 agent（驗證碼，以及 /lockdown、/new、/usage、/attacks 這些指令照常有效）。等待期間按下的建議動作按鈕或回覆建議按鈕會保留，之後可以再按；回覆建議不會再被用掉。
- `shentu dispatch`（#158）：參數錯誤時先顯示用法，在讀設定之前，不論是誰執行；參數正確時，`stats` 和 `repair` 才要求 root（Windows 是系統管理員）。`sudo shentu dispatch repair` 在 `*.jsonl.bad` 裡每一行壞紀錄只保存一次，每日報告會寫出搬出的行裡有幾行是新加入的。
- Next 15：在 import `next/headers` 的檔案裡，`const h = await headers(); h.get(name)` 和同步的 `const h = headers()` 會當成 `headers().get(name)` 來讀。所以這樣讀到的 Host header 傳進 redirect 時，由 js-open-redirect-next 回報（讀 `headers()` 的 SSRF 和命令注入規則也一樣）（#157）。
- Koa：Koa application 或 router 用 `use` 註冊的 middleware，只要函式把第一個參數當成 context 用，它的 context 經過解構和別名也追得到，和路由 handler 一樣（`app.use(async (ctx) => { const { host } = ctx.request.headers; ... })`）。用 `use` 註冊的 HTTP client interceptor 或函式庫的 plugin，不會被當成 middleware（#157）。
- Laravel：`$request->sort` 這種 magic property，以及 `->when($request->input('sort'), fn ($q, $s) => $q->orderBy($s))`（還有 `->unless`）的閉包，由 php-sqli-orderby-identifier 回報。前提是 `$request` 可能是 Laravel 的 request：檔案用到 Illuminate 的類別、宣告成 `Request` 型別、有類別 extends Controller，或在用到 Illuminate 的專案裡，它是函式沒有型別的參數（#157）。
- SSRF：檔案裡有更多種可能在別處替換 `console.log(u)`、`JSON.stringify(u)`、`String(u)` 的寫法時，URL 的 host 檢查不再保留：`Function` 當成值、`Function.prototype.bind`、`getPrototypeOf`、`Reflect.construct`、vm 的執行函式、`GLOBAL`、`top`、`this` 除了讀具名成員以外的用法、require 或 import `console` 模組，以及 `require(` 或 `import(` 的參數不是單純字串，或用到 `createRequire`（#157）。

### 升級說明

- 有上面這些寫法的檔案，在 `console.log(u)` 之後的 `fetch(u)` 會再次回報 SSRF，和 v0.4.3 之前一樣。因為新的 Next、Koa、Laravel 讀法，攻擊偵測判斷為可到達的路由也可能改變。

### 已知問題

- 型別名稱以 `Request` 結尾的資料物件（`SearchRequest $request`）會被當成 Laravel 的 request，和 FormRequest 一樣。
- Next 的 `headers()` 只在檔案自己 import `next/headers` 時才追。
- 來源是 request 的呼叫時，`in_array($request->query('s'), [...], true) ? $request->query('s') : null` 不會被當成值的檢查（magic property 的同樣寫法會）。

## v0.5.2 — 2026-11-20

- 子 agent 專用模型（#135）：`[agents] base_url`、`model`、`api_key_env` 可以讓子 agent 用自己的模型；沒設定時沿用 `[llm]`。這台主機以外的模型（127.0.0.0/8、::1、localhost 以外都算）必須設 `[budget] monthly_tokens`，否則一個子 agent 都不跑，也不送出任何請求；用過外部模型的派遣，會在給 agent 的訊息、存檔和每日報告裡寫明。送出去的內容照舊遮罩。外部模型回錯誤時只留狀態碼，因為錯誤內容可能引用金鑰；不跟隨轉址；連線失敗時只保留失敗的種類，不帶網址。`[llm]` 的錯誤會先把金鑰（原樣和常見的編碼形式）換掉再截斷。
- 子 agent 同時執行（#136）：用這台主機以外的模型時，若本月 token 上限還容得下一整次派遣，而且有設 `monthly_cost` 時花費還不到一半，子 agent 會同時執行，各分得相同的 token 份額；模型在這台主機上（任何位址寫法）時，仍然依序執行。
- `sudo shentu dispatch repair`（#134）：把存檔裡讀不懂的行搬到 `<date>.jsonl.bad`，並刪掉空行，自動事件調查就不必再等最多 72 小時。檔案以一次 rename 換掉，存檔鎖改為 `dispatch/.lock`。在 Windows 上，它和 `dispatch stats` 要以系統管理員身分執行；其他使用者執行時，兩個指令都會在讀設定之前先這樣提示。
- 操作者回饋（#137）：派遣的回報下面，bot 會給已配對的人「👍 有用」「👎 誤報」兩個按鈕，只能按一次，7 天內有效。`sudo shentu dispatch stats [--days 7] [--json]` 依角色加總數字，並在固定範圍內提出調整建議（步數 4～10、token 20,000～60,000、檢討提示詞）。工具只可能被建議移除、絕不新增；目前不會產生工具建議。Shentu 不會自己套用。
- 平台（#138）：角色只拿得到這個平台能用的工具，其餘列為沒有檢查；只有 Linux 會提出封鎖建議；macOS 目前只跑 `surface`；自動事件調查只在 Linux 執行，其他平台不占每日次數。

### 升級說明

- `[agents]` 的模型若寫成區網位址或主機名稱（包括網路上另一台機器的 Ollama），都算這台主機以外；127.1、0.0.0.0、[::]、這台主機自己的區網 IP 也一樣。必須設 `[budget] monthly_tokens`。

### 已知問題

- 用單價高的模型時，一次派遣的花費可能一次就超過 `monthly_cost` 的一半；上限擋得住之後的呼叫，擋不住那一次。
- bot 和巡檢各自為自己的派遣預留額度，看不到對方的預留。
- 自動事件調查目前在 Windows 和 macOS 上都不執行，包括 incident 角色（在 Windows 上，這個角色可用的工具較少，也不提出建議）。

## v0.5.1 — 2026-11-20

- 派遣存檔（#112）：每一次子 agent 派遣，在回報交回 agent 之前，都會存進 `state_dir/dispatch/<date>.jsonl`（檔案 0600、目錄 0700，保留 30 天）。存的是角色、狀態與原因（固定字詞）、各項計數，以及建議封鎖的位址（canonical 形式）和 Telegram 閘門對每一個的判定。子 agent 或紀錄寫的文字一律不存。寫入和讀取時都會逐欄檢查；其他使用者寫得進去的存檔，或是連結，都不會讀。每日報告新增一段，列出最近一天的派遣，位址遮罩成 /24（IPv6 是 /64）。
- 建議動作按鈕（#116、#122）：Telegram 的回答派遣過子 agent 之後，bot 會列出建議封鎖的位址。當下通過 `block_ip` 從 Telegram 執行時的檢查（含 #108 的閘門）、而且以 canonical 形式寫的，各附一顆按鈕，最多五顆；其餘只寫出固定字詞的原因。按鈕只帶派遣 id 和一個序號。按下後會再檢查一次，接著要按 ✅（`[bot] confirm = 4` 也一樣），然後才封鎖。換了配對、超過 24 小時、按第二次（重啟後也一樣），或存檔裡的位址不同，都會拒絕。
- 自動事件調查（#117），預設關閉（`[agents] auto_incident`）：巡檢推送的 L3 群組，會自動派出唯讀的 `incident` 子 agent。每輪最多一次、每天最多 3 次、同一個群組一天一次；未查證或溢出的群組不派，沒設 `[budget] monthly_tokens` 或已用超過 80% 也不派，存檔或 `log.jsonl` 讀不到結尾時也不派。通知只有固定字詞和數字；它的建議動作也用同樣的按鈕，只在 bot 服務執行中、而且能改防火牆時才送出。
- bot 和 `shentu chat` 的每月 AI 預算上限：`log.jsonl` 讀不到結尾時，當成預算已用完。

### 已知問題

- 子 agent 仍然依序一個接一個執行，而且只在 Linux 上開發與測試。
- 存檔裡有寫到一半的行時（例如磁碟滿了），自動事件調查會停最多 72 小時（通常約兩天），直到那個檔案離開讀取的範圍；每日報告會寫明。
- 用 7B 的本機模型時，子 agent 常常用完 6 步，被標成未完成。

## v0.5.0 — 2026-11-20

- 子 agent（Linux、單機）：在 Telegram bot 和 `shentu chat` 裡，agent 可以用 `dispatch` 工具把唯讀的檢查交給最多 3 個子 agent，每個子 agent 一個角色：`patrol`、`surface`、`attack` 或 `incident`（#101）。每個角色有固定的唯讀工具清單；子 agent 不能封鎖或解除封鎖位址、不能發通知、不能用 skill，也不能再派遣。子 agent 依序一個接一個執行。巡檢輪次和 eval bot 不會派遣。
- 上限：每個子 agent 最多 6 次模型呼叫、每步 3 個工具呼叫、每次 2048 個輸出 token、合計 40,000 個 token、5 分鐘；一次派遣最多 120,000 個 token、12 分鐘，月預算照樣適用。每次呼叫前先估 token、呼叫後再計入，reasoning token 也算。被上限擋下、或沒有照規定格式回報的子 agent，會標成未完成並寫出原因，不會當成已完成。被時間上限切斷的模型呼叫不再重試。
- 回報：每個子 agent 用固定的 JSON 格式回答（發現、建議、沒查到的項目），逐欄檢查並遮罩，agent 讀到時標成 untrusted。封鎖建議只是建議：派遣之後，同一段對話裡每一次 `block_ip` 或 `unblock_ip` 都要按 ✅ 按鈕，`[bot] confirm = 4` 也一樣，直到 `/new` 為止；稽核紀錄會寫出是哪一次派遣。bot 的進度訊息會顯示子 agent 的步驟（最後 12 步），不認得的工具名稱顯示成「未知工具」。

## v0.4.3 — 2026-11-20

- SSRF：URL 的 host 檢查過之後，`console.log(u)`、`JSON.stringify(u)`、`String(u)` 不再讓檢查失效，條件是檔案只用 `console`、`JSON`、`String` 來呼叫（沒有同名的參數或宣告，沒有 `console.log = f`），也沒有可能在別處替換這些呼叫的寫法（`globalThis` 這類 global 物件除了讀具名成員以外的用法、`eval`、`Function(`、`with` 敘述、改寫內建物件的 prototype）（#119）。
- JavaScript 的路由 handler：字串 key 的解構 `const { 'x-forwarded-host': xfh } = req.headers` 追得到，這個值改由 js-ssrf-host-header 回報，不再是 js-ssrf-http-request。Koa 的路由 handler 參數解構時取了 `request`（`({ request }) => request.header.host`），在這個檔案或專案裡的其他檔案有 import `koa`、`@koa/router` 或 `koa-router` 的情況下，就當成 Koa 的 context（#119）。
- 新的來源：Next 15 的 `(await headers()).get(...)`，這樣讀到的 Host header 傳進 redirect 時由 js-open-redirect-next 回報；php-sqli-orderby-identifier 讀 Laravel 的 `Request::query(`、`Request::get(`（`DB::raw`、`->orderBy(`）（#118）。
- NestJS：整個 `@Headers()` 物件的欄位寫進回應（`res.send(` 裡的 `h['x-note']`）時，由 js-xss-response 回報（#125）。
- 去除重複回報。同一個呼叫只由一條 SQL injection 規則回報：兩條規則在同一行的同一個呼叫都會報時，其中一條讓另一條回報（`yields_to`）。`->where(` 用 Symfony 的 `$request->query->get(` 時只歸 php-sqli-doctrine-query-text，不再同時由 php-sqli-drupal-db-query 回報；`DB::raw(...)` 放在 php-sqli-laravel-raw 的呼叫裡，在 laravel-raw 也回報時歸 laravel-raw。同一行的其他呼叫照樣回報（#125）。另外在 SSRF 規則裡，`h` 是整個 NestJS `@Headers()` 物件或 Express 的 `r.headers` 時，`const x = h` 之後的 `x.host`（`x['Host']`、`x['x-forwarded-host']` 也一樣）只由 js-ssrf-host-header 回報，不再同時由 js-ssrf-http-request 回報；名稱也可能是 request 的其他值時（在某個分支裡是 `r.query`），兩條規則照樣回報（#132）。

### 升級說明

- 有些回報換了規則：用 request 輸入組成的 `sa.text(...)` 改由 python-sqli-sqlalchemy-text 回報，不再是 python-sqli-dbapi-format（#118）；用字串 key 解構出來的 Host header 改由 js-ssrf-host-header 回報，不再是 js-ssrf-http-request（#119）；兩條 SQL injection 規則都會報的呼叫只報一次（#125）。php-sqli-laravel-raw 的修正建議加了說明：ORDER BY 的欄位和排序方向要對照白名單。因為這些變動，攻擊偵測判斷為可到達的路由也可能改變。

### 已知問題

- 用 `app.use` 註冊的 Koa middleware 不是路由 handler：它的 context 只認直接的寫法（`ctx.request.headers['x-forwarded-host']`），不追解構（`const { host } = ctx.request.headers`），也不追別名（`const h = ctx.request.headers`）。
- 每個分支都重新指定過的名稱，在分支之後仍然會被追蹤，所以會多報。
- Next 15 的 `const h = await headers(); h.get(name)` 和同步的 `h = headers()` 還不算來源。
- JavaScript 的只讀呼叫判斷還看不到 `Object.getPrototypeOf`、`Function` 的別名、`Reflect.construct`、`vm.compileFunction`，也看不到經由 `this`、`GLOBAL`、`top` 取得的 global 物件；`typeof window` 會讓整個檔案回到「`console.log(u)` 就讓檢查失效」。

## v0.4.2 — 2026-11-20

- JavaScript 規則不管路由 handler 的 request 叫什麼名字都追得到：不叫 `req` 的參數（`(r, s) =>`）、不叫 `ctx` 的 Koa context、別名（`const q = r`、`const h = r.headers`），以及解構（`({ headers }, res) =>`、`const { headers, hostname: hn } = r`、`const { host } = req.headers`）。所以 `r.hostname`、`r.get('host')`、`c.host` 和解構出來的 `headers` 現在都會回報；這樣讀到的 Host header 歸 js-ssrf-host-header，其他 header 歸 js-ssrf-http-request。request header 的索引照 Node 的存法以小寫讀（`r.headers['Host']`）。在 SSRF 規則裡，Koa 的 `ctx.header` 和 `ctx.request.get(` 也算來源，Host header 另外加上 `ctx.request.header.host` 和 `ctx.request.headers.host`（#106）。
- NestJS：在讀 `@Req()` 的 13 條 JavaScript 規則裡（SSRF、SQL 與 NoSQL injection、命令注入、程式碼執行、路徑穿越、LDAP injection、反序列化），`@Request()` 和 `@Req()` 一樣算 handler 的 request。兩者都只有在這個檔案或專案裡的其他檔案 import 了 `@nestjs/common` 或 `@nestjs/core` 時，才算 NestJS 的；其他情況就是普通的物件（#103、#106）。
- Python：用反斜線接到下一行的 `global`、`nonlocal`，會讀到整個敘述結束，下一行的名稱也算宣告（#103）。
- SSRF：URL 的 host 檢查過之後，`a = u.valueOf()` 再改 `a`，或用計算出來的名稱呼叫 `u` 的方法（`u['valueOf']()`、`u[k](...)`），都會讓檢查失效，和 `a = u` 一樣（#103）。

### 修正

- systemd 的 userdb 目錄（`/etc/userdb`、`/run/userdb`、`/run/host/userdb`、`/usr/local/lib/userdb`、`/usr/lib/userdb`）有任何項目、或讀不到時，伺服器自己的帳號擁有的網站紀錄不再能當封鎖依據：userdb 可以加上 `/etc/passwd`、`/etc/group` 看不到的帳號和群組成員（#113）。
- 防禦性檢查：封鎖檢查也認得 `inet_aton` 寫法（`3405803788`、`0xcb.0.113.12` 等），封鎖檢查和 campaign 都把 `::ffff:a.b.c.d` 當成 `a.b.c.d`；存取紀錄本來就不會產生這些寫法（v0.4.0 起只收一般位址，`::ffff:` 也會讀成 IPv4），實際行為不變（#113、#124）。

### 升級說明

- 有些 JavaScript 的發現會換一條規則回報：以 `r.headers['X-Forwarded-Host']` 或 `const { host } = req.headers` 讀的 Host header，改由 js-ssrf-host-header 回報，不再是 js-ssrf-http-request；專案沒有 import NestJS 時，`@Req()` 由 js-ssrf-http-request 回報；`const { host } = req.headers` 寫進回應，js-xss-response 不再回報，因為從 v0.4.1 起 Host 不算 XSS 的輸入。攻擊偵測認定可到達的路由也可能跟著變。
- 主機的 systemd userdb 目錄有任何項目時，升級後伺服器自己的帳號就不再算獨立：v0.4.1 能當封鎖依據的紀錄（例如 Rocky 9 的 nginx），會重新判成 `web_user_writable`。條件見 `docs/attack-detection-limits.zh-TW.md` 的「哪些網站紀錄可以支撐封鎖」。Ubuntu 24.04、Rocky 9 的預設安裝五個目錄都不存在，不受影響（4fcfc52 在兩台實機驗收時實測）。
- 更正 v0.4.1 的說明：「用其他寫法記下的位址（方括號、port、zone、多寫的 0）也會被拒」在實際的存取紀錄流程裡碰不到，因為紀錄只收一般位址；只有紀錄裡出現 IPv4-compatible（`::a.b.c.d`）或 NAT64（`64:ff9b::a.b.c.d`）位址時才會生效。已發版的 v0.4.1 條目原文不改。

### 已知問題

- Koa handler 的 context 是看 handler 怎麼用它來認（`c.request`、`c.response`、`c.state`、`c.throw`、`c.assert`，或設定 `c.body`、`c.status`、`c.type`）；其他參數都當成 Express 的 request。解構的參數也當成 Express 的 request，所以 Koa 的 `({ request }) =>` 不會追。巢狀解構（`{ headers: { host } }`）和字串 key（`{ 'x-forwarded-host': xfh }`）也不追；後者仍會回報，只是歸 js-ssrf-http-request。
- request 的別名以函式為單位記錄；別名只要在某一個分支被重新指定，就所有路徑都不再追。
- 檔案沒有 import NestJS、專案裡也沒有時，`@Req() req` 不算 NestJS 的：它的 `req.headers.host` 會同時被 js-ssrf-host-header 和 js-ssrf-http-request 回報。
- URL 檢查偏向保守：檔案裡任何地方有 `global u` 或 `nonlocal u`（含反斜線接行），整個檔案的 `u` 都不算檢查過；檢查後的 `fetch(u.valueOf())`，以及無害的 `u['toString']()`，也會回報。

## v0.4.1 — 2026-11-20

- 主機盤點會對開了 HTTP/2 的 nginx 1.9.5～1.31.8 提出警告（`listen ... http2`，或對 server 生效的 `http2 on`）：CVE-2026-123007 和 CVE-2026-123633 是 HTTP/2 的記憶體錯誤，用戶端可以讓 worker 當掉。請更新到 1.31.9 或 1.30.7，或 distro 修補後的套件；更新前先改回只用 HTTP/1.1 就沒有這個問題。這只是建議，不會改設定。套件的 changelog 已列出這兩個 CVE（distro 已 backport 修補）時不警告；distro 的公告進了 OSV 之後，套件掃描就會報，這項檢查補的是 nginx.org 的套件和自行建置的 nginx，套件掃描看不到這兩類。
- 伺服器自己的帳號（例如 Rocky Linux 的 `nginx`）擁有的網站紀錄，在沒有其他程式用這個帳號執行時，可以和 root 擁有的紀錄一樣當封鎖依據：沒有 PHP-FPM pool、systemd unit、crontab、supervisord 程式、sudo 或 doas 規則、登入 shell，巡檢時也沒有伺服器本身以外的程序；帳號資料只來自檔案，要查的也都讀到了。有任何一項讀不到，紀錄就仍是 `web_user_writable`。共用的預設帳號（`www-data`、`apache`、`nobody`）一律不算。其他條件見限制文件 `docs/attack-detection-limits.zh-TW.md` 裡，說明哪些網站紀錄可以當封鎖依據的那一段。
- nginx 送到 journald 的存取紀錄（`access_log syslog:server=unix:/dev/log,...`）會被讀取，並逐行查證：只有經 syslog、由 nginx 本身的程式、以 worker 的帳號在 `nginx.service` 裡送出的那一行才算查證。其他程式送出的行會讀，但不算查證。
- 新增 `shentu log-trust suggest`，列出讓這台主機的網站紀錄能當封鎖依據的改法：nginx 送 journald 的那一行設定、調高 journald 對 nginx 筆數上限的 drop-in、`kernel.yama.ptrace_scope = 1`，以及 PHP-FPM 改用各自帳號的 pool。它只列出建議，不會改任何設定。
- Apache 的模組改用名單判斷：只做設定、限制存取、快取或 proxy 的模組沒有影響；會用子程序帳號執行程式的模組，以及 `RewriteMap` 的 `prg:`，要 `ptrace_scope` 1 以上；`mod_php`、`mod_cgi` 和不認得的模組都算應用程式碼。
- 在路由 placeholder 那一段、帶有 `;` 參數的攻擊命中（例如 `/user/:id` 的 `/user/42;x`），現在會到 L2；先前只到 L1。
- L3 用的回應大小基準，現在只排除被升到 L2 的請求；沒有對應到路由的命中和雜訊命中，都會算進基準。
- 規則更準確：同一行被兩條規則重複回報的情況，現在只由一條規則回報（Host header 和 SSRF、SQL injection、`ORDER BY` 識別字）；解析後的 URL 已用固定的白名單比對過 host，SSRF 就算已檢查。有些 finding 會多出來，有些會不見，攻擊偵測認定能進入的路由也會跟著變。

### 修正

- 從 Telegram 呼叫 `block_ip`，現在只封鎖 Shentu 已查證證據的位址：已查證的 L2 或 L3 攻擊群組有列出它，或有 sshd 自己寫下的 SSH 登入紀錄。其他位址在 Telegram 一律拒絕，要到伺服器上用 `shentu chat` 查看並封鎖，和 v0.4.0 對未查證嘗試的說法相同。先前攻擊群組沒有列出的位址（超出群組列出的 10 個、群組已從紀錄中清掉，或紀錄裡的寫法不同），只看 SSH 登入紀錄，所以沒有 SSH 紀錄的位址，可以憑未查證的嘗試從 Telegram 封鎖。一個群組最多列出 10 個位址，所以即使是已查證的 L2 或 L3 群組，第 11 個以後的位址從 Telegram 也會被拒絕，這是設計如此，要到伺服器上封鎖。
- 在伺服器上，超出群組列出位址數的位址，會和列出的位址一樣被拒絕，同網段的其他位址也是；群組被併進溢出彙總之後也一樣。紀錄裡寫法不同的位址也會被拒絕，包括方括號、port、zone、多寫的 0（例如 `203.0.113.012`，兩個讀法都比對），以及寫在 IPv6 裡的 IPv4。已查證的群組只放行它列出的那個位址。溢出彙總或依 sink 彙總的群組，來源超過它保留的 hash 數（64 個）之後，會拒絕所有沒列出的位址；營運者可以在伺服器上覆寫。

### 升級說明

- v0.4.0 已知問題寫的「預設安裝的 nginx 紀錄不能當封鎖依據，v0.4.1 會處理」，現在的狀況如下（完整說明見 `docs/attack-detection-limits.zh-TW.md`）：Debian 12、Ubuntu 24.04 的 nginx 仍是 `web_user_writable`（`www-data` 也是 PHP 的帳號），要把存取紀錄送到 journald，並設 `ptrace_scope` 1；Debian 12、Ubuntu 24.04 的 Apache 在 `ptrace_scope` 1 時就算查證；Rocky 9 的 nginx 仍是 `web_user_writable`，因為預設的 `nsswitch.conf` 也會問 sss，確定沒在用 SSSD 時把 sss 去掉，PHP-FPM 用 `apache` 帳號，就算查證；Rocky 9 的 httpd 要設 `ptrace_scope` 1，如果 `mod_lua` 還載入著，各處也都要 `AllowOverride None`。
- 紀錄改判為查證之後，新的嘗試會進查證過的群組；舊的未查證群組最多保留 7 天才到期，這段期間同一個目標可能出現兩組。新的 journald 來源第一次只從最新的位置開始讀，不讀以前的紀錄。

## v0.4.0 — 2026-11-18

- 攻擊偵測（Linux）：每一輪巡檢都會讀網站伺服器的紀錄，挑出打向這台主機真實存在的漏洞的請求。它只告警，不會自己封鎖。看不到什麼、可能漏掉什麼，列在 `docs/attack-detection-limits.zh-TW.md`。
- 漏洞面：每日巡檢把這台主機已知的漏洞存到 `state_dir/surface.json`，其他輪次讀這份：程式碼稽核的結果，同一個檔案看得出來時，附上註冊該 handler 的路由（#84）；應用程式相依套件與已安裝 OS 套件的漏洞公告，版本照 dpkg 與 rpm 的規則比較；已安裝的 WordPress 外掛與版本（#91）。漏洞面不存在、讀不到或超過 26 小時，會在該輪的通知和報告裡寫明，不會默默沿用。
- 紀錄來源：nginx 與 Apache 設定裡寫的 access log（含自訂格式）、PHP-FPM 的紀錄，以及應用程式 unit 的 journald；每輪從上次讀到的位置接著讀，紀錄輪替也接得上（#85）。只有確定只有 root 寫得進去的紀錄才算已查證；其他紀錄裡的嘗試標成未查證，告警會寫出原因。
- 27 條攻擊特徵，由 Shentu 自己撰寫，或從審過的 nuclei-templates（MIT，見 `detect/sig/NOTICE`）起草；請求最多解碼兩輪後比對（#87）。只打到有漏洞 handler 的路由是 L1；同時帶有該漏洞類別的 payload 是 L2；L3 要有生效的跡象：回應大小和這條路由平常差很多，或錯誤紀錄在有漏洞的檔案與行號出現例外（#90）。請求在可能藏 payload 的地方被截斷時是 Unknown。主機沒有的漏洞算雜訊。
- 告警是偵測器自己寫的純文字，經由通知管道送出，不經過模型。嘗試依網段（/24 或 /64）、目標與等級分組，同一組一天只送一次。L1 只在每日報告裡計數，不推送；Unknown 要同一個目標 24 小時內累積 20 筆才推送。樣本裡的敏感參數會遮罩，每日檔案 `state_dir/reports/attacks-<date>.txt`（保留 30 天）的位址也會遮罩（#90、#91）。`shentu detect [--since] [--json]` 讀一輪並判定，但不送出也不存檔；`attack_attempts` 工具和 bot 的 `/attacks` 列出最近一天的群組。
- `block_ip` 與攻擊偵測：偵測器看過的 IP，要有它自己的、已查證的 L2 或 L3 群組，經營運者確認後才會封鎖。來自未查證紀錄、只有 L1 或 Unknown 的嘗試，以及內部位址，一律拒絕，除非營運者在伺服器上（`shentu chat`）用 `override_unverified` 覆寫；Telegram 永遠不行。只列在多個來源合併的溢出彙總組裡的 IP，有沒有覆寫都拒絕（#91）。在 Ubuntu VM 上驗收：已查證紀錄裡的攻擊判成 L3，可以封鎖；未查證紀錄裡的最多到 L2，從 Telegram 封鎖會被拒絕。
- `block_ip` 的 SSH 證據，只有 journald 裡 sshd 自己的事件確認過的登入才算（#91）：在 sshd 自己的 unit（cgroup）裡由其他程式寫進 journald 的 sshd 紀錄（例如用 `logger`），不能再當封鎖依據；v0.3.1 會封。偽造進文字紀錄的本來就會拒絕。
- 引擎：跳過不會改變結果的 summary 計算，分析時也少做複製。以 Mac 本機的 user CPU 時間量，WordPress 掃描比 v0.3.1 快約 34%，TypeScript 專案快約 22%，結果完全相同（#92）。以 Ubuntu 24.04 VM（arm64、4 CPU、4 GB）上的實際經過時間量，同一台機器依序跑三版，WordPress 掃描 97.2 秒（v0.3.1 120.0 秒、v0.3.0 72.1 秒），比 v0.3.1 少 19%；三版都是 2279 個檔、43 筆結果，記憶體高峰都在 848～858 MB；每日巡檢（root）126 秒（v0.3.1 146 秒、v0.3.0 99 秒）。benchmark 不變：已公開漏洞 97 個抓到 16 個、已修版本誤報 1 個；holdout 30 個抓到 3 個；TypeScript 18 個抓到 1 個、已修版本誤報 1 個。
- `tools/detecteval`（CI 會跑）用合成的請求衡量攻擊偵測（#94）：從 nuclei-templates v10.5.2 轉出的請求：同類別的特徵比中 40.5%（有分類的 3822 個模板中 1548 個）。這是請求行的比中，不是告警；8 個應用程式、152 條路由的一般請求：誤報 0 筆，95% 上限約 0.8%（其中只有 363 筆在追蹤參數以外有差異，所以只能說誤報率低於約 0.8%）；針對測試主機真實存在的漏洞的模板：10 個中 3 個告警，其中 2 個只到 L1（payload 在請求本文裡）。

### 修正

- 同一個請求在同一行程式碼命中多條規則時，只發一則告警，並列出所有規則，不再每條規則各發一則（#97）。
- 套件 CVE 的告警不再附上路由的說明；那段說明只放在你自己程式碼的告警裡（#97）。
- 紀錄檔或上層目錄透過 ACL 讓其他帳號可以寫入時，原因裡會寫出是哪個帳號，例如 `ACL grants write to www-data (uid 33)`（#97）。
- 用非 root、也不在 `systemd-journal` 或 `adm` 群組的帳號跑巡檢時，SSH 的結果會標成「只讀到一部分」（#97）。

### 升級說明

- 修正之前的 v0.4.0 版本存下的攻擊紀錄（每條規則一組），載入時會合併成新格式（每行程式碼一組）（#97、#98）。升級前的次數是下限：同一行上不同類別的規則被不同請求打到時，次數可能偏低。這只影響顯示的次數，不影響告警或封鎖。v0.3.x 沒有攻擊紀錄，從 v0.3.x 升級不需要合併。

### 已知問題

- 攻擊偵測只支援 Linux。
- access log 不記錄請求本文（POST 表單、JSON、上傳檔）：payload 放在那裡就看不到，這類請求最多是 L1。
- 特徵比對的是攻擊的原始寫法。改寫過的寫法（其他編碼、加料的路徑、SQL 裡的註解或其他空白字元、用引號拆開的指令）可能漏掉。
- Debian、Ubuntu、Rocky Linux 預設安裝的 nginx，v0.4.0 都會把 access log 判成 `web_user_writable`（網站帳號可寫），所以只能告警、不能當封鎖依據。Debian、Ubuntu 上 nginx 和 PHP 都用 `www-data`，風險是真的（Ubuntu 的紀錄屬於 `www-data:adm`，logrotate 也用 `create 0640 www-data adm` 建檔）；Rocky 上 nginx 用 `nginx` 帳號、PHP-FPM 用 `apache` 帳號，寫不到 nginx 的紀錄，是 v0.4.0 判得比較保守。手動改擁有者，下次輪替時會被改回去。v0.4.1 會處理。Rocky Linux 的預設 httpd 設定會載入白名單以外的模組，所以 Apache 的紀錄一律判成 `web_user_writable`；這些模組的評估排在 v0.4.1。
- 目前還沒有針對個別 WordPress 外掛漏洞的特徵。
- 掃描仍比 v0.3.0 慢：WordPress 約 35%（上面 Ubuntu VM 的實際經過時間），TypeScript 專案約 20%（Mac 本機的 user CPU 時間，#92）。
- v0.3.1 仍未解決的：CVE-2021-23664 的已修版本仍會被報；WordPress 上傳暫存路徑的 `filesize()`；`markup` 不會追進先組在變數裡的標記。

## v0.3.1 — 2026-11-16

- 程式碼稽核規則從 70 條增加到 127 條（PHP 25 → 51、Python 22 → 43、JavaScript 與 TypeScript
  23 → 33）。PHP：WordPress、Laravel、Symfony、Joomla、Drupal、CodeIgniter、Yii 與 Smarty 的危險呼叫，
  socket 與 HTTP client、XML DTD、template 字串、加密金鑰與 shortcode（#76）。Python：keyword 參數（`args=`、`search_filter=`、`where=`）、ldap3 filter 與經過 helper 的流向（#36）。JavaScript 與
  TypeScript：Koa 和 Express 串接式回應、BSON 與 launder 的 sanitizer、Host header 的 open redirect 與 SSRF；
  `.execute(` 只在可能是資料庫 client 的物件上才算（#70）。
- v0.2.5 列出的已知誤報，已經在引擎修正：有 import `typeorm` 的檔案，TypeORM repository 的呼叫不算 MongoDB 查詢；檔案也用了 MongoDB repository、driver 或 Mongoose 時照樣算（`unless_imports`，#59）；`shell: true` 的 `spawn()` 和 `execFile()`，只有指令或參數帶有輸入才報，只有選項帶輸入不報（一個危險呼叫可以有多個 `[[args]]`，#62）；每條路徑都設了 `Content-Type: text/event-stream` 的 Server-Sent Events handler 不算 XSS （`unless_content_type`，#58；`unless_at`，#57）；`->get_settings()` 只在繼承 `\Elementor\Widget_Base` 的類別裡才算 Elementor widget 的輸入（#60）；用 `array_map` 加上回傳常數的 callback 組出的 placeholder 清單不算輸入（#61）；`zipfile.ZipFile(request.files[...])` 開的是上傳檔的串流，不是路徑（`unless_subscript`，#67）。
- `js-ssrf-http-request`（漏報）：Koa、hapi 與 Fetch API 寫法的 Referer／Origin 之前沒被當成輸入，
  `fetch(ctx.request.header.referer)`、`fetch(request.headers.referer)`、`fetch(request.headers.get('x-callback-url'))`
  會漏報；現在都算輸入（Host 除外，那是 Host header 規則的輸入），規則格式的 `source_args` 也新增 `"!name"` 排除值。
  `php-sqli-string-concat` 與 `php-sqli-prepare-query-text`（重複回報）：輸入寫進 `prepare()` 的查詢文字時，兩條規則之前在同一行都會報一次，現在只由 `php-sqli-prepare-query-text` 回報。benchmark 的數字不變。
- 引擎：`new URL(a, base)` 的 `a` 以 `/` 或 scheme 起始時，路徑和 query 只取自 `a`（#63）；同一個檔案裡已知類別的物件，呼叫它的方法會追進方法裡（#64）；用 regex 從起始處比對、固定值起始的檢查（`re.match(re.escape(base) + r'/[a-z]', url)`）對 redirect 和 URL 規則算是檢查（#65）；會追進回傳字串常數的
  helper（#66）；`markup`：輸出類的危險呼叫，只有在輸入前面接著 HTML 標記時才報（#71）；recursive 的呼叫 cycle
  會一直追到結果不再改變，成本只算一次，WordPress 呼叫沒有跟完的檔案從 48 個少到 4 個（#72）；Host header 規則用
  `route_input = false`，Express 模型也認得 Koa 的 `ctx`（#50）。
- 主機盤點會對 Apache 2.4.55～2.4.70、載入 `mod_http2` 並在 `Protocols` 開了 `h2` 或 `h2c` 的情況提出警告（CVE-2026-119618；請更新到 2.4.71，更新前先把 `Protocols` 設成只有 `http/1.1`）（#54）。可能載入 `mod_http2` 或開啟 h2 的檔案讀不到時（沒有權限、不能用的連結），
  這項會列為沒有檢查，不再當成沒事；警告也註明發行版已經 backport 修補時可以不理會。
- 程式碼稽核：接續的掃描在跑到上次位置前就沒有時間時，保留原本的位置，位置也改用根目錄的路徑記錄；vendor、
  node_modules 和 WordPress 的程式碼資料夾只在網站根目錄之下才算；`wp-content/blogs.dir/*/files`，以及沒有網站首頁檔的 `/var/www/<uploads|files>`，都算上傳資料夾；`authorized_key_unparsed` 只列出前 20 個行號（#73）。
- 登入紀錄沒有完整讀到時（root 以外的帳號看不到 journald 的系統紀錄、讀不到 `auth.log` 或 `secure`、
  紀錄只讀到一部分），hourly 和每日報告都會把 SSH 登入列為沒有檢查。之前這個情況只會寫「nothing new」（#80）。
  寫出的原因是紀錄不能用的真正理由（例如沒有任何登入的主機：journald 沒有 sshd 紀錄，也沒有文字紀錄），只有缺少權限時才建議用 root 執行；macOS 的 sshd 紀錄不在 Shentu 讀的地方，報告會明說 macOS 上沒有 sshd 紀錄來源。
- Linux 版本查 DNS 時不再帶 EDNS(0) 記錄，和 glibc 一樣：有些 DNS 伺服器（例如 VMware NAT 的
  DNS）回應這樣的查詢時會少了位址，所以每次查詢（OSV、GitHub）都失敗，回報「no such host」。
  如果查詢還是失敗，每日報告的 Not checked 會提示檢查這台主機的 DNS（#80）。
- `block_ip` 不再執行在這兩個情況：IP 的 SSH 登入紀錄只來自主機上任何人都能寫入的文字紀錄（`verified` 為 false），
  或是登入紀錄讀不到。管理員自己確認過紀錄後，可以在 `shentu chat` 用 `override_unverified` 照樣執行；
  從 Telegram bot 不能用，每個確認等級都一樣。
  這個檢查只看 SSH 登入紀錄：用 `log_search` 讀 syslog、nginx 或應用程式的紀錄而提出的 `block_ip`，
  不在檢查範圍內，要由管理員自己確認。
  journald 裡完全沒有 sshd 紀錄的主機（只有文字紀錄），只要 IP 有 SSH 登入紀錄，`block_ip` 都不會執行，
  不管紀錄上寫的是什麼時間；這時不能從 Telegram 執行，只能在伺服器上用 `shentu chat` 加 `override_unverified`。
  `ssh_logins` 最多回查 720 hours，和這個檢查一樣（#80）。因為登入紀錄可能是偽造而不執行時，訊息會列出這些紀錄所在的文字紀錄檔。
- macOS：binary plist 的 array 和 dictionary 項目也計入讀取上限，UTF-16 字串每個字元算 9 bytes；最後一個字元是 space 的程式路徑照原樣保留；同一個 PID 出現在兩行 `ps` 輸出時標為 `parse_error`；`periodic_conf_files`
  多於 16 個時，沒有讀到的會列出來（#80）。CI 在 macOS 15 上跑 `go vet` 和 `go test`（#81）；還沒有提供 macOS
  執行檔。
- 測試裡看起來和憑證一樣的測試值，改成執行時才組出來，repo 裡不再有金鑰格式的字串（#77）。
- 和 v0.3.0 比較的 benchmark：已公開漏洞 97 個抓到 16 個（原本 15 個），修補版誤報 1 個（原本 0 個，見下方）；
  保留測試案例（held-out）30 個抓到 3 個（原本 2 個），沒有修補版誤報；TypeScript 案例 18 個抓到 1 個、
  修補版誤報 1 個（n8n），都沒有變。

### 已知問題

- CVE-2021-23664（`@isomorphic-git/cors-proxy`）：`js-ssrf-http-request` 在修補版仍會報出。這個 proxy 在通過
  allowlist 檢查後才送出 `req.url`，引擎還不會把這個檢查當成 sanitizer；之後會使引擎辨別送出請求前的這類檢查。
- 規則變多，掃描時間變長，因為每個檔案要跑的規則更多：WordPress 多了 40～60%，依機器而定（在 Ubuntu VM 上，
  程式碼稽核從 73.8 s 變成 120.0 s，每日巡檢從 100 s 變成 144 s，結果數與 RSS 最高值都沒有變），TypeScript
  專案多了 43%。根本的修正排在 v0.3.1 之後。
- `block_ip` 的檢查只包含 SSH 登入紀錄（見上方）：根據別的紀錄要求的 `block_ip`，要由管理員自己決定。
- `php-deserialization-phar-wrapper` 仍會把 WordPress REST attachments controller 裡對上傳暫存路徑做的
  `filesize()` 報出來：引擎還分不出上傳檔的 `tmp_name` 和客戶端填的 `name`。
- `markup` 不會追蹤先在變數裡組成的 HTML 標記（`const h = '<p>' + x; ctx.body = h`）。

## v0.3.0 — 2026-11-13

- 支援 Windows Server 2022 與 2025，已在 GitHub 提供的 Windows Server 2022/2025 測試機上驗證（amd64，
  另建置 arm64）：Windows 收集器只透過 Windows API
  讀取主機（登錄檔、服務、程序、通訊埠、帳號、排程工作、事件記錄、WMI 與防火牆），不用
  PowerShell，也不執行外部指令。
- Windows 檢查：自動啟動項目（Run 機碼、服務、排程工作、啟動資料夾、WMI 事件訂閱）、未啟用
  NLA 的 RDP、SMB 簽章與 SMBv1、不安全的 WinRM、防火牆設定檔、Defender 狀態與排除清單、
  登入失敗與記錄被清除。
- 依 Microsoft 每月安全性更新（MSRC）比對缺少的 Windows 更新，並以 CISA KEV 清單標出已被
  利用的漏洞、優先列出。
- IIS：從 `applicationHost.config` 取得網站根目錄；程式碼稽核會讀取 ASP 與 ASP.NET 頁面，
  找出 webshell 與上傳目錄裡的腳本，UTF-16 頁面也包含在內。
- 兩個 Windows 服務：`Shentu`（巡邏）與 `ShentuBot`（Telegram），從 `%ProgramFiles%\Shentu`
  以 `shentu service install [--bot]` 安裝；設定與狀態放在 `%ProgramData%\Shentu`，只有
  SYSTEM 與 Administrators 能存取。
- `ssh_logins`、`processes`、`accounts_audit` 與 `log_search` 工具可在 Windows 使用（登入
  事件、程序清單、本機帳號、事件記錄）。
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
- macOS（新增，只讀取，不用 sudo）：系統版本、用戶（dscl）、程序、開放的連接埠
  （netstat；macOS 不列出時改用 lsof）、應用程式的網路防護、SIP、Gatekeeper、FileVault、XProtect、
  launchd 與別的開機或定時自動執行的位置、sshd 設定，以及安裝的 app 與 Homebrew 套件。
  系統版本與 Apple 的軟體更新清單（gdmf.apple.com）比對；套件回報「說不出有沒有漏洞」，
  因為 OSV 沒有 Homebrew 的資料。只用自製的測試資料驗證過，還沒有在真的 Mac 上試過。
  登入項目（Background Task Management）不會讀取，所以 macOS 的開機自動執行位置都會標為 partial。
  periodic.conf 與 daily、weekly、monthly.local 逐行列出（不列沒有內容的行與說明行；說明行是以 # 開始、
  沒有 " ' $ ` 這幾個字元的行，這些檔案通常不長），periodic_conf_files 指到的檔案也會讀；
  與 Apple 公開版本相同的 /etc/defaults/periodic.conf 不列。
- 程式碼稽核的資料夾寫成 `/var/www/html/`（最後多一個 `/`）或 `/` 時，接續上次的位置稽核
  不會再把整個資料夾跳過。資料夾改為先整理成標準寫法，所以更新版本後的第一次稽核找不到上次的位置，
  會從開始完整檢查一次。
- sshd 設定：被 Include 的檔案（`Include sshd_config.d/*.conf`）裡有 `Match` 時，
  主檔案裡 Include 之後的設定也會照樣讀到（sshd 每讀完一個 Include 都會回到原本的狀態），
  例如之後的 `PermitRootLogin yes` 會報出來。Include 多於 4 次或設定檔多於 256 個時，列為沒有讀到。

### 已知問題

- 從原始碼建置現在需要 Go 1.26 以上（原本是 1.23）：Windows 的收集程式用到 golang.org/x/sys，這是第二個外部套件。
- Windows 版只讀不寫：不支援 `block_ip` 與 `unblock_ip`。
- Windows Server 2019 為 best effort：預期可用（相同的 Windows API，build 17763），但沒有在 GitHub 提供的測試機上驗證。
- `shentu setup` 還不能在 Windows 上執行，設定需要手動撰寫。
- Windows 執行檔沒有程式碼簽章，也沒有 MSI；SmartScreen 或防毒軟體可能發出警告。

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
