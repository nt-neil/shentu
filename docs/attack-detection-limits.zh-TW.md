# 攻擊偵測：v0.4.1 已知限制

[English](attack-detection-limits.md)

偵測怎麼運作、告警怎麼讀、為什麼封鎖要你確認：見[攻擊偵測怎麼運作](attack-detection.zh-TW.md)。

v0.4.1 內建 27 條攻擊特徵（和 v0.4.0 相同），不會為了攔下攻擊的各種改寫寫法而擴充。
以下是已知會漏掉的情況。漏掉只會影響告警：漏報，或判得比較輕。這些情況都不會讓 Shentu 封錯 IP。
v0.4.0 不會自動封鎖：`block_ip` 一定要經營運者確認。攻擊紀錄也會檢查：有攻擊嘗試的 IP，只有它自己的 L2 或 L3 群組、而且已查證（不是多個來源合併的溢出彙總組），才能封鎖。只打到路由（L1）、無法判定（Unknown）或來自未查證紀錄的嘗試，都不能當封鎖依據；這時仍可依 journald 本身確認過的 SSH 登入紀錄封鎖。內部位址（私有、loopback、CGNAT 等）一律拒絕。`override_unverified` 會解除上面除了一項以外的所有檢查，而且只能在伺服器上（`shentu chat`）使用，從 Telegram 一律拒絕：未查證、L1 或 Unknown 的嘗試不再擋下封鎖，SSH 登入紀錄不再檢查，內部位址也可以封，封鎖完全依營運者自己查看紀錄後的判斷。列在溢出彙總組裡的 IP 仍然拒絕，除非它另外有自己已查證的 L2 或 L3 群組。從 v0.4.1 起，從 Telegram 呼叫 `block_ip` 只封鎖 Shentu 已查證證據的位址（已查證的 L2 或 L3 群組有列出它，或有 sshd 自己寫下的 SSH 登入紀錄）；其他位址，包括沒有任何群組列出的，在 Telegram 一律拒絕，要由營運者在伺服器上處理。一個群組最多列出 10 個位址：即使是已查證的 L2 或 L3 群組，第 11 個以後的位址從 Telegram 也會被拒絕，這是設計如此，要到伺服器上封鎖。

## 完全看不到的部分

- **只支援 Linux**：攻擊偵測只讀 Linux 主機的紀錄。
- **部分紀錄格式會被拒絕**：會讀 nginx 和 Apache 的存取紀錄，設定檔裡的自訂格式也讀。格式裡有 Shentu 不支援的欄位、用了 `escape=none` 或自訂時間格式，都會被拒絕。
- **看不到協定層的攻擊**：access log 記錄的是伺服器解析完成的請求，不記錄承載請求的 HTTP/2 frame 或 TLS record。所以針對協定層本身的攻擊，這裡完全看不到，例如 nginx 的 HTTP/2 漏洞 CVE-2026-123007 和 CVE-2026-123633。這類風險改由主機盤點依版本和設定判斷：受影響的 nginx 開了 HTTP/2，就會提出警告。distro 是否已 backport 修補，是從套件的 changelog 判斷。沒有 changelog 的映像（Ubuntu minimized 映像、部分容器映像），修好了也可能仍然警告；這種情況請以 distro 的公告為準。移除了 nginx 套件、留下設定檔，又另外裝了自行編譯的 nginx（不在盤點會找的位置）時，可能不會出聲。nginx 的 `include` 如果經過群組可寫、或不屬於 root 的目錄（例如 `sites-enabled` 指到部署帳號的目錄），HTTP/2 檢查會列成「未檢查」。這是刻意保守的設計，不是誤報。
- **看不到請求本文**：存取紀錄不記 POST 本文、JSON 或上傳檔，放在那裡的 payload 永遠看不到；這種請求打到路由時，最多只到 L1。
- **最多解碼兩輪**：網址編碼最多解兩次（含 `%u` 和過長的 UTF-8）。base64、gzip 和其他編碼都不解。
- **無法判定的請求只計數，L1 不推播**：請求被截斷、可能藏有 payload（Unknown）時只計數；同一個 sink 在 24 小時內累積到 20 次才推播。L1 的嘗試只計數並列入報告，不會推播成告警。
- **未查證的紀錄不能拿來封鎖**：Shentu 無法查證的紀錄裡的嘗試，會標成未查證，告警會寫出原因。`block_ip` 不會拿它當封鎖依據；只有營運者在伺服器上才能覆寫（見上文）。原因有這幾種：
  - `web_user_writable`：應用程式碼執行的帳號（PHP-FPM 的、應用程式 unit 的，或 web 伺服器和 PHP 共用的 `www-data`、`apache` 這類帳號）擁有這個紀錄檔，或寫得到它上層的目錄。Debian、Ubuntu 上的 nginx 預設就是這樣，因為 logrotate 用 `www-data` 建立紀錄檔。伺服器在自己的程序裡執行應用程式碼（mod_php、有 handler 的 mod_lua、nginx 的應用模組），以及應用程式碼可以 ptrace 伺服器的 worker，也都算這一種。怎樣才能放行，見下一節。
  - `untrusted_owner`：紀錄檔、指向它的連結或它上層的目錄，擁有者不是 root；或紀錄檔可被群組或其他人寫入，或上層目錄可被其他人寫入。
  - `unverified_source`：Shentu 無法確認只有 root 能改動這個紀錄檔，例如上層目錄可被某個群組寫入、但不知道群組成員，有 ACL，或帳號資料庫、連結讀不到。讀取時的檔案不是判定時的那個（中間被換掉），以及沒通過檢查的輪替檔，也算這一種。web 伺服器的設定沒有讀完整，或設定列出的紀錄來源超過 Shentu 讀取的上限時，所有紀錄都會因為這個原因變成未查證。
  - `not_regular_file`：紀錄檔不是一般檔案。
  - `symlink_not_followed`：紀錄檔要經過連結才看得到，Shentu 不跟隨連結。
  - `client_from_header`：伺服器從請求的 header 取用戶端位址（nginx 的 realip、Apache 的 mod_remoteip），紀錄裡的 IP 是代理或用戶端自己寫的。
  - `custom_format`：紀錄格式不是標準格式（nginx combined 或 main、Apache combined 或 common）。照樣比對，但無法排除用戶端寫的欄位讓其他欄位錯位。
- **不是 root 時讀到的 SSH 登入**：只有 root，或 systemd-journal、adm 群組的成員，journald 的 SSH 登入紀錄才算完整，可以當封鎖依據。wheel 群組的成員（RHEL、Fedora）其實可能讀得到整份 journal，但會被當成只讀到一部分，所以它讀到的 SSH 登入不能當封鎖依據。反過來，adm 群組的成員一律當成讀得到全部，即使 journal 沒有開放給 adm（例如 journal 只放在 /run/log/journal）。

## 哪些網站紀錄可以支撐封鎖

紀錄要能支撐封鎖，前提是應用程式碼執行的帳號改不了它的內容：不能直接寫檔，不能透過開著這個檔案的 worker 寫，也不能冒充伺服器送紀錄。這裡假設的攻擊者是已經能以網站應用程式的身分執行程式碼（例如利用 PHP 漏洞）。不在防禦範圍內的：root 被拿下，以及 nginx 或 Apache 本身被攻破（worker 執行攻擊者的程式碼），這兩種情況任何紀錄檢查都擋不住。

- **伺服器自己的帳號**：紀錄檔屬於 nginx worker 或 Apache children 執行的帳號時，在下列條件全部成立下，會和 root 擁有的一樣被信任：
  - 沒有別的東西以這個帳號執行，不論是同 uid 還是同群組：沒有 PHP-FPM pool、沒有其他 systemd unit、沒有 crontab，沒有 linger 的使用者管理程序，沒有 supervisord 的 program，沒有 sudo 或 doas 能以它執行的規則，帳號也沒有可登入的 shell；巡檢當下也沒有任何不是伺服器本身程式（root 擁有的 nginx 或 httpd）的程序以它的 uid 或群組執行；以上任何一項讀不到，都不算；
  - 伺服器本身不執行應用程式碼；
  - 帳號在 `/etc/passwd`，而且只有它用這個 uid；
  - 帳號資料庫只來自檔案；systemd 的 userdb 目錄（`/etc/userdb`、`/run/userdb`、`/run/host/userdb`、`/usr/local/lib/userdb`、`/usr/lib/userdb`）沒有任何項目，也都讀得到，因為 userdb 可以加上這些檔案看不到的帳號和群組成員；
  - 設定完整讀到。

  這時也不必擔心 worker 被 ptrace，因為沒有應用程式帳號追蹤得到它。共用的預設帳號（`www-data`、`apache`、`nobody` 等）不論 Shentu 讀到什麼，都不算伺服器自己的帳號，因為 Shentu 沒讀到的東西可能也以它執行。
- **Apache 的模組**：只做設定、存取控制、快取或代理的模組沒有影響。以 children 帳號執行外部程式的模組（`mod_actions`、`mod_ext_filter`、`mod_include`、`mod_suexec`、`mod_userdir`、`mod_cgid`），以及 `RewriteMap` 的 `prg:`，要求 `kernel.yama.ptrace_scope` 至少為 1，這樣那些程式才追蹤不到 children；告警會寫明這點。`mod_lua` 只要有任何指令提到 Lua，或有任何 `AllowOverride` 不是 `None`，就算應用程式碼。`mod_cgi`、`mod_php`，以及 Shentu 不認得的模組，都算應用程式碼。
- **nginx 經 journald**：nginx 也可以把存取紀錄送到 journald（`access_log syslog:server=unix:/dev/log,nohostname combined;`）。journald 會替每一行記下送出者的 unit、帳號和執行檔，這三項任何程序都改不了。Shentu 從 `nginx.service` 的紀錄讀這份存取紀錄；只有經 syslog、由 nginx 的執行檔、以 worker 帳號、在這個 unit 裡送出的那一行，才算已查證。PHP 執行的 `logger` 在別的 unit、是別的執行檔，所以照樣讀，但不算已查證。前提有五個：
  - `/dev/log` 是 journald 的 socket；
  - `nginx.service` 用絕對路徑啟動 nginx；
  - 只有一個 `user` 指令；
  - 這個 tag 沒有被其他 nginx 紀錄使用；
  - 除非 worker 的帳號是伺服器自己的帳號，否則 `ptrace_scope` 至少為 1。

  原本的檔案紀錄照舊保留，判定也不變。nginx 同時寫檔案和送 journald 時，同一個請求會收到兩則告警：一則來自 journald 的行，算查證；一則來自檔案，不算查證，並標示不能從 Telegram 封鎖。journald 是在收到訊息後，依送出者的 pid 去讀 /proc 填 unit 和執行檔；送出者送完立刻結束、pid 又剛好被 nginx 的 worker 重新使用時，理論上可能被記成 nginx 的。這個時機 web 帳號控制不了；較新的 systemd 用 SCM_PIDFD 取得送出者，沒有這個問題。

預設安裝的判定如下，依據是在 GitHub runner 和 Ubuntu VM 上的量測。`ptrace_scope`：Ubuntu 實測 1，Debian 推定 1，Rocky 推定 0。

| | 預設 | 怎樣能放行 |
|---|---|---|
| Debian 12、Ubuntu 24.04 的 nginx | `web_user_writable`（`www-data:adm 0640`，而 `www-data` 也是 PHP 的帳號） | 加上 journald 那一行，並且 `ptrace_scope` 為 1 |
| Debian 12、Ubuntu 24.04 的 Apache | `ptrace_scope` 為 1 時已查證（`root:adm 640`，預設 19 個模組） | `ptrace_scope` 為 1 |
| Rocky 9 的 nginx | `web_user_writable`：第一次輪替前是 `root 0644`，之後是 `nginx:root 0640`；預設的 `nsswitch.conf` 也查 sss，帳號資料庫不完整 | 從 `nsswitch.conf` 拿掉 `sss`，而且 PHP-FPM 以 `apache` 執行：輪替前後都是已查證 |
| Rocky 9 的 httpd | `ptrace_scope` 為 0 時是 `web_user_writable`（告警會寫明設 `ptrace_scope=1` 就能放行） | `ptrace_scope` 為 1；如果還載入 mod_lua，每個 `AllowOverride` 都要是 `None` |


**Rocky 9 與 sss**：預設安裝的 Rocky 9 上，nginx 紀錄在其他檢查之前就判定為 `web_user_writable`，原因是 `/etc/nsswitch.conf` 寫的是 `passwd: files sss systemd`。只有 `passwd`、`group`、`initgroups` 這幾行都只列 `files`、`compat`、`systemd` 時，shentu 才承認伺服器自己的帳號。SSSD 提供的帳號或群組（來自 LDAP、Active Directory 或 FreeIPA）不在 shentu 讀得到的檔案裡，它可能和伺服器帳號同一個 uid，也可能把應用程式的帳號放進伺服器的群組。shentu 不放寬這一條。確定沒有在用 SSSD 的主機，可以這樣拿掉 sss：

1. 先確認 SSSD 沒有提供任何東西：`systemctl is-enabled sssd` 和 `systemctl is-active sssd` 顯示 disabled、inactive；`/etc/sssd/sssd.conf` 不存在，或裡面沒有任何 domain；也沒有人用 `/etc/passwd` 以外的帳號登入。
2. 看 authselect 目前的設定：`authselect current` 會列出設定檔（預設是 `sssd`）和啟用的功能，例如 `with-faillock`、`with-mkhomedir`。
3. 改用不含 sss 的設定檔，保留原本的功能並留備份：`authselect list` 會列出這個設定檔（`local`，較舊的版本叫 `minimal`），接著執行 `authselect select local <原本的功能> --backup=before-shentu`。authselect 管理期間不要手動改 `nsswitch.conf`，下一次 `authselect apply-changes` 會把它蓋回去。如果沒有 authselect 設定（`authselect current` 顯示沒有），就自己從 `/etc/nsswitch.conf` 的 `passwd`、`group`、`initgroups` 三行拿掉 `sss`。
4. 確認：`grep -E '^(passwd|group|initgroups):' /etc/nsswitch.conf` 裡沒有 `sss`，而且 `getent passwd nginx` 仍查得到。

拿掉之後的影響：SSSD 提供的帳號和群組查不到，也無法登入（PAM 的 `pam_sss` 會跟著設定檔一起拿掉）；來自 SSSD 的 sudo 規則和 automount 對應失效；它們擁有的檔案只會顯示數字。本機帳號不受影響。要還原就執行 `authselect backup-restore before-shentu`。下一輪巡檢時 shentu 會重新判定；上表那一列的其他條件（PHP-FPM 以 `apache` 執行）仍然要滿足。

`shentu log-trust suggest` 會印出適用於所在主機的修改：
- journald 那一行；
- 解除 journald 對 nginx 的單一 unit 限流的 drop-in。預設每個 unit 每 30 秒最多保留 10000 筆，多的會丟掉，忙碌時段的攻擊就會漏看；它也會列出 journald 過去一天丟掉的筆數。
- `kernel.yama.ptrace_scope = 1`。之後一般帳號不能再對自己正在執行的程序掛除錯器。
- PHP-FPM pool 改用獨立帳號。

它不會改動任何東西：營運者自行決定套用哪些，下一輪巡檢會重新判定。不建議在 logrotate 改紀錄檔的擁有者，原因有兩個：nginx reopen 時會不會把檔案交還給 worker，還要在 VM 上確認；套件升級時，發行版的設定也可能被蓋回去。

## 可能漏掉的請求

- **改寫過的路徑穿越**：特徵只認最直接的寫法。攻擊者在路徑中多塞斜線或反斜線、`./` 片段或 `;` 路徑參數，就可能比不到。
- **改寫過的 SQL 注入**：以下寫法可能比不到：
  - 在關鍵字之間插入註解；
  - 用空格、Tab 以外的空白字元；
  - 用註解收在值的結尾；
  - 對數字下不帶引號的恆真條件。
- **改寫過的指令注入**：以下寫法可能比不到：
  - 用完整路徑呼叫指令；
  - 用特徵清單以外的指令；
  - 用引號把指令名稱拆開。
- **改寫或換位置的 Log4Shell 查詢**：用巢狀查詢拼出來的寫法可能比不到。放在 Referer 標頭裡的也可能比不到，因為目前不檢查這個標頭。
- **改寫過的反序列化內容**：
  - PHP 序列化物件的長度前面加了正負號，或是自訂序列化格式，都可能比不到。
  - Java 那條特徵裡，比對原始序列化位元組的分支永遠不會命中，因為比對前會把文字轉小寫；base64 和 hex 形式照樣比得到。
- **其他 PHP 串流包裝**：特徵涵蓋 `php://filter`、`php://input`、base64 的 `data:`、`expect://` 和 `zip://`。其他包裝（例如 `glob://`、`compress.zlib://`），以及不是 base64 的 `data:`，都比不到。`phar://` 不在這條特徵裡，但值以它開頭時，反序列化那條特徵比得到。
- **Flarum 開放重導向（composer-cves）沒有斜線的寫法**：重導目標只寫通訊協定加冒號、沒有 `//`，可能比不到，但瀏覽器照樣會跳到外站。
- **Flarum 掛在名稱有點的目錄下**：Flarum 登出路由有錨定，前面只能是目錄，或是緊接在路由前面的 `index.php`。Flarum 掛在名稱有點的目錄下（例如 `/v1.2/`）會漏判。
- **路由參數裡有編碼過的 `/`**：路由是用解碼後的路徑比對。路由參數的值裡有編碼過的 `/` 時（例如 `/files/:name`），請求對不上這條路由；能吃多段路徑的路由不受影響。
- **WordPress 外掛**：目前沒有針對個別 WordPress 外掛漏洞的特徵。有人攻擊主機上有漏洞的外掛時，只有被通用類別特徵抓到才看得見，而且不會對應到那個外掛的 CVE。

## 參數名稱與路徑段

類別特徵也會拿參數名稱和路徑的每一段來比對，所以一般流量裡能被比中的文字變多了。

- 參數名稱的命中和參數值的命中一樣：路由是同類別時，會到 L2。
- 路徑段的命中，只有在路由的 placeholder 取到那一段時才算 L2；否則路由維持 L1，命中列為未錨定（Unanchored）。
- 用正規表示式寫的路由，capture group 就是 placeholder。沒有 group 的路由，路徑段命中只到 L1。group 裡的固定字（例如 `(user|list)`）會被當成 placeholder 取到的值，所以那個字被比中時會到 L2。
- placeholder 的值同時從清理掉 `;` 參數的路徑和保留 `;` 參數的路徑取，所以命中落在 placeholder 那一段的 `;` 參數裡時（例如 `/user/:id` 對上 `/user/42;…`），會到 L2；落在路由自己的字或掛載前綴的 `;` 參數裡，維持 L1。
- 有些 router 會丟掉路徑裡的 `;` 參數，處理函式根本看不到。Shentu 仍會把 `;` 參數的值當成 payload 比對，所以這種請求可能多報一筆 L2。
- 路由的回應大小基準從它的正常回應學，只排除被命中升到 L2 的請求（未錨定和雜訊的命中仍會算進基準）。某條路由的正常請求如果常在 placeholder 或參數取到的地方含類別特徵文字，而且回應較大，基準仍會偏小，L2 比較容易拿到大小證據；單一證據的 L3 上限是 high。

## 為了不誤判一般文字而收窄的特徵

有三條類別特徵收窄過，以下所列的三種形式不會再被比中：

- 常見英文字後面接空格和括號，例如「system (」；
- 搜尋字串裡的引號、空格、兩個減號；
- 分號後面接 id，再接其他字。

其他形式的一般文字仍然會被比中，例如：

- 特徵列出的函式名稱、空格、括號，括號裡一開頭是引號、`$` 或另一個呼叫（單純的巢狀括號不會命中）；
- 值的結尾是引號、`--`，後面再接至少一個空白或 `-`；
- 分號後面接一個短的指令名稱。

代價是會漏掉一些寫法：函式名稱和括號之間有空格的呼叫，只有參數看起來像程式碼（引號、`$` 或另一個呼叫）時才抓得到；引號後面隔了空格時，只有 `--` 必須收在值的結尾，`#` 和 `/*` 隔了空格照樣抓得到；分隔符號後面的 id，後面再接參數或引號時抓不到。

## 實測偵測率

數字來自評估工具（`tools/detecteval`，PR #94），用的是 integ adff9e6（#87、#90、#91 已併入）的特徵組和比對方式，數字就是和本文件同一棵樹裡的 `tools/detecteval/baseline.json`。數字已包含參數名稱、路徑段、錨定路由和三條收窄的特徵。CI 的 detect-eval 每次改動都會重新量測，只要有一個數字和 baseline 不同就會失敗；v0.4.1（integ 37dc016）量到的數字完全相同。

數字的意思：

- **「偵測到」**：模板轉成的請求行裡，有任一條同類別的特徵命中。這不是告警，也不是主機上的 L2。
- **「誤報」**：一般請求裡，有任一條掃描器以外的特徵命中。
- **樣本是合成的**：由 nuclei 模板轉出的請求，加上用固定種子產生的請求，不是真實流量。

結果：

- **全部模板：偵測率 40.5%（3822 個中 1548 個）。**
  - 資料來源：nuclei-templates v10.5.2（commit 5442582a），`http/` 底下 11835 個模板。
  - 無法轉換的 1143 個、未分類的 6618 個、`rce-unspecified` 的 252 個，都不算進分母。
- **正常流量：1216 筆請求，沒有誤報。**
  - 請求來自 8 個應用（WordPress、Django、Flask、Laravel、Express、Immich、Nest、Next）的 152 條路由，每條 8 筆。路由的填充值用完時，會加上追蹤參數，讓每筆都不同。
  - 1216 筆請求中，去掉追蹤參數（活動標記、點擊 id、語言、防快取參數）後不重複的只有 363 筆；以這個數量，只能說誤報率大約在 0.8% 以下（95% 信賴上限），而且這些請求只來自 152 條路由。這兩個數字由工具自己計算（`baseline.json` 的 `normal_distinct`、`normal_routes`）。
- **主機真的有這個漏洞時：10 個模板中 3 個有告警。** 逐項如下，取自 `-explain-host`。

| CVE | 告警 | 原因 |
|---|---|---|
| CVE-2017-9841 | L1 | 有專屬特徵。payload 在請求本文（body），存取紀錄看不到，所以只到 L1。 |
| CVE-2021-3129 | L1 | 有專屬特徵。payload 在本文，只到 L1。 |
| CVE-2024-21641 | L2 | 有專屬特徵。 |
| CVE-2021-21315 | 沒有 | 沒有專屬特徵。類別特徵比中路徑，但類別特徵不論類別，都不會對應到套件的 CVE，所以只算雜訊。 |
| CVE-2021-23337 | 沒有 | 沒有專屬特徵。payload 在本文。 |
| CVE-2022-29078 | 沒有 | 沒有專屬特徵，類別特徵也沒比中。 |
| CVE-2023-0297 | 沒有 | 沒有專屬特徵。payload 在本文。 |
| CVE-2023-3452 | 沒有 | 沒有專屬特徵。同類別的類別特徵比中路徑，但套件 CVE 要有專屬特徵才算數，所以只算雜訊。 |
| CVE-2024-3136 | 沒有 | 沒有專屬特徵。payload 在本文；類別特徵比中路徑，同樣只算雜訊。 |
| CVE-2025-69971 | 沒有 | 沒有專屬特徵。這個漏洞是寫死的密鑰，請求行本來就沒有 payload。 |

不帶這些 CVE 的模板，在主機上都沒有告警：Shibboleth SP 的登出路徑不再對應到 Flarum 的 CVE-2024-21641。

「類別相符，而且主機有這個套件漏洞」升為 L1 的做法，延到 v0.4.1 再評估。
