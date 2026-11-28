# 更新紀錄

CHANGELOG.md 的繁體中文版，網站的繁中頁讀這份。兩份的版本與日期必須一致，
每個版本都要有內容（`go test ./cmd/sitegen` 會檢查）。

## v0.5.8 (unreleased)

- 新增 `reference` 等級，給只看呼叫寫法、不看輸入的規則用（只有 `sources = []` 的規則可以用）。app_code_audit 和聊天會把這類發現排在其他發現之後，另外標示出來；每日報告只用一行寫出筆數。這類發現不會主動送出通知，也不交給攻擊偵測。`info` 和 `alert` 兩個等級不變。
- 用 `apt-mark hold` 鎖住的 Debian 或 Ubuntu 套件（dpkg 狀態 `hi`），以及標成要移除、但還裝著的套件（`ri`、`pi`），現在和已安裝的套件一樣會被檢查。以前套件清單只收 dpkg 的 `ii`，所以鎖住的套件不會被檢查，也不會被列出來（v0.5.7 的已知問題）。已經放到磁碟上、但沒有完整安裝的套件，會讓套件清單標成部分（partial），並在那裡寫出名稱和狀態（最多 20 個，其餘只寫數量）。檔案都已解開的套件（unpacked、half-configured、triggers awaited、triggers pending）會照 dpkg 記錄的版本檢查。half-installed 或狀態讀不懂的套件不檢查，會連同狀態列在 `packages_not_checked`，排在只剩設定檔的套件（config-files，只會被列出來）前面。最多列 20 個，其餘的數量寫在 `packages_not_checked_more`。工具說明也寫了這兩個欄位。
- block_ip 讀伺服器的 DNS 伺服器和預設閘道（`/etc/resolv.conf`、systemd-resolved 的那一份、`/proc/net/route`、`/proc/net/ipv6_route`）時，和它檢查的 SSH 連線一樣改經主機來源讀取：replay 或其他主機的盤點，不會拿跑檢查的這台機器來回答。這幾個檔案有在、但讀不到時，現在會拒絕封鎖（`state_error`）；以前讀不到也照樣往下做，把清單當成空的，所以閘道或 DNS 伺服器可能被封鎖。檔案不存在（沒有 systemd-resolved、沒有 IPv6）仍然只是沒有這一項。
- app_code_audit、app_vulns（lock 檔和 site-packages）以及 WordPress 外掛清單，現在讀的是主機來源裡的檔案，和一開始用到的 web root 一樣：replay 或其他主機的盤點，不會拿跑檢查的這台機器來回答。symlink 仍然不跟隨，檔案只在還是掃描時看到的那一個時才讀，上限也都相同。web root 或 app 路徑有在、但讀不到時（沒有權限，或 replay 裡沒有它），現在會列在稽核的 `not_checked`；以前會當成空的資料夾稽核過去。用這一版之前錄的 fixture 做 replay 時，這些路徑都會說讀不到，不會說成不存在。
- package_vulns 會讀完 OSV 回答的每一頁：OSV 一次查詢最多給 1000 筆公告，並寫明下一頁；以前只讀第一頁，所以 kernel 的清單停在 1000 筆（在 Ubuntu 24.04 上，比另一套掃描工具少了 383 個 CVE）。一個套件超過 10 頁時，其餘的會寫在 `partial`，不會默默截斷。
- Ubuntu 上的 package_vulns：一則 USN 會包括它修正的每一個版本，它的 alias 會列出只有其他版本才有的 CVE（USN-7980-1 列了 CVE-2025-11187，OSV 只把它列在 25.10 和 26.04，不在 24.04）。現在一則 USN 只算 OSV 對這個套件、在主機這個版本上也列出的 CVE，所以其他版本的 CVE 不會再在這台主機上標成正在被利用（KEV），也不會算進弱點面；第三方 PHP 或 nginx 和 php.net、nginx.org 的公告比對時，也不會被當成 OSV 已經列出的 CVE。一則 USN 所屬的套件如果沒有任何以 CVE 命名的公告可以判斷版本，這則 USN 會算進 `kev_unchecked` 並寫出名稱，不會沒有說明就不算。
- Windows：Shentu 自己不跟隨 link 開啟的檔案（派遣紀錄、AI 預算預留檔、自動事件和稽核的鎖），現在都用同一個 handle 檢查和使用，這個 handle 開啟時不跟隨 symlink 或 junction。以前是先看檔案，再用名稱開啟，然後用一種在 Windows 上分不出來的方式比對兩者：中間被換成 link 的檔案，會經由那個 link 被開啟。去重的檔案（Windows Server 的 Data Deduplication）照常開啟；其他種類的 reparse point 會寫出原因，不會開啟。
- Windows：site_profile、程序、開著的連接埠、帳號、SSH 這幾個工具，log_search，以及 Python 的 site-packages 檢查，現在和 macOS 的一樣，依主機來源讀到的是不是 Windows 來判斷，不看跑檢查的這台機器。replay Windows 主機的讀取，或從另一台機器檢查 Windows 主機，不會再得到 Linux 的答案；site-packages 也會比對 Windows venv 的 `RECORD` 路徑（和 Windows 一樣不分大小寫，舊版 pip 寫的 `\` 也認得），套件 `RECORD` 裡列出的 `.pth` 不會再被當成來路不明。Windows 主機上看得到 Apache 時（有 `httpd.exe` 的程序或服務、`C:\Apache24\conf\httpd.conf` 或 `C:\xampp\apache`），site_profile 的 `risks` 裡會多一筆 unchecked：`unchecked:notyet:apache:windows`，表示那裡的 Apache 還沒有檢查，所以不會判斷 CVE-2026-119618（HTTP/2）。每日報告把它列在「這一版還沒有檢查的元件」這一段，不放在缺少權限那一段。
- `app_vulns` 和每日巡檢會檢查 Docker image 裡的 Python 套件，用 PyPI 比對 OSV，並標出 CISA KEV。套件是從磁碟上 Docker 的 overlay2 image 庫讀出來的，不會啟動容器，也不會問 Docker daemon。每個有 tag 的 image，照 overlayfs 的方式把各層依序合在一起：同一個檔案以上層的為準；刪除的標記只刪掉同一個資料夾裡的同名檔案；不透明的資料夾會讓下層在它裡面的檔案都看不到。之前 image 裡的套件完全不會被檢查。image 庫存在但讀不到時（不是 root、有檔案讀不到、超過 50 個 image、200 層或 200,000 個檔案的上限），會在報告裡寫成沒有檢查，日報裡這些說明各自一行；這台沒有 Docker image 庫時會另外說明。image 庫的資料夾是 symlink 時不會跟過去；巡檢中止時，還沒讀的 image 會寫明沒有檢查。放在 containerd 存放區的 image（新版 Docker 預設放在這裡：`/var/lib/containerd`，或 `daemon.json` 開了 `containerd-snapshotter`），這版不會讀，`partial` 會寫明沒有檢查，不會說成沒有 image；日報會把它列在「這一版還沒有檢查的元件」。只有讀的是這台機器本身時才讀 image 庫：replay 會寫明 image 沒有檢查。image 裡的 `.pth` 一律不會被當成工具自己的。
- package_vulns 不指定套件時，結果會分開列出：確定已經有修補的有幾筆（`fix_available`，每個套件也有），沒有確認的有幾筆（`fix_unconfirmed`）。算成有修補的情況：公告是發行版的更新公告（DSA、DLA、USN、RLSA、ALSA、SUSE-SU）或 ALAS。php.net、nginx.org 的項目也算進 `fix_available`：PHP 或 nginx 本身已經發出修正版，但你用的套件庫（例如 sury）不一定已經打包。其他的（例如 Debian 或 Ubuntu 追蹤頁上的 CVE 項目）都算未確認：這時不會逐筆去抓公告來判斷，`fix_note` 也寫明「未確認」不等於「沒有修補」。之前這兩種算在同一個數字裡；指定 `package` 時，仍然會列出每一筆的 `fixed_version`，但不列這兩個數字。
- site_profile 在 Linux 和 macOS 上多了兩種風險。`sudo:nopasswd`（警告）：sudoers 讓人不用密碼就能執行所有指令。包括 NOPASSWD 之後的指令裡任何一個是 `ALL`（NOPASSWD 一直有效到 PASSWD 為止）、指令的 alias 是 ALL 或看不出內容、指令路徑是資料夾或路徑裡有萬用字元（`/usr/bin/`、`/usr/bin/*`，裡面包括 sh；萬用字元只在參數裡的不算）、被當成密碼遮掉的指令，或是對所有人、某個使用者或某個 runas 帳號的 `Defaults !authenticate`；不論寫在哪個 sudoers 檔，或對象是群組、ALL。唯一的例外是 cloud image 的預設使用者：寫在 `/etc/sudoers.d/90-cloud-init-users`（只認這個路徑）、對象只有 cloud-init 的 `default_user`（從 `/etc/cloud/cloud.cfg` 和 `cloud.cfg.d/*.cfg` 讀，不讀 user-data；用讀不出來的寫法設定的，例如 `{name: x}`、key 加了引號或 JSON，就當成沒有）的這種規則，是 `sudo:nopasswd:cloud-init`（資訊，只列在報告裡），文字寫明只有這個使用者限定用金鑰登入時才安全。只對部分指令設 NOPASSWD，或只對部分指令的 `Defaults!cmd !authenticate`，是 `sudo:nopasswd:some`（資訊）。每條規則都會寫出它執行什麼、以哪個帳號執行。規則會照 sudo 的方式讀過每一個 `#include`、`@include` 和 `includedir`（檔名有點或以 `~` 結尾的會跳過）。有檔案讀不到，或 sudoers 來自 sss、ldap 時，會寫成 `unchecked:sudoers`，不會當成沒有這種規則。錄製時只在 sudoers 檔裡保留 sudo 的 tag（`/etc/sudoers`、`/etc/sudoers.d/*`，以及這兩者 include 進來的檔），而且只在規則行裡、tag 後面接的是指令時才保留（`ALL=NOPASSWD: /path`、`(root) NOPASSWD: DEPLOY`、`sudoedit`、option），所以 replay 也會照原樣讀到這些規則；其他地方的密碼遮罩和之前一樣，另外 `(x) PASSWD: !<密碼>` 和 `FOO: PASSWD: ALL-<密碼>` 這兩種寫法裡的值，現在也會遮掉。`reboot:pending`（警告）：更新之後還在等重新開機，舊的 kernel 或函式庫仍在執行。Debian 和 Ubuntu 看 `/run/reboot-required`（附上它列出的套件）；其他發行版看 `/boot` 裡有沒有比執行中更新、而且是同一種的 kernel（`+debug`、UEK 和發行版自己的 kernel 分開比）。執行中的 kernel 不在 `/boot` 裡時（例如容器）不會比較。
- file_changes 和 log_search 的 hard link 檢查，現在也和其他檢查一樣，透過 host 來源讀主機：replay 或另一台主機的 survey，讀的是那台主機的檔案，不是執行檢查的這台機器；在 Windows 機器上讀 Linux 或 macOS 主機的記錄也一樣（路徑保留原本的「/」：讀資料夾、log 的 allowlist、找 site-packages、找 WordPress 外掛、app_vulns 和 app_code_audit 的 path 參數，以及稽核從上次停下的地方繼續的時候，都照那台主機的寫法處理）。host 來源的檔案資訊多了 ctime（file_changes 照舊會算進去：mtime 被改回舊時間的檔案一樣會列出）和 hard link 的數量；這些檢查只在 Unix 上做（Windows 上的檔案資訊會寫明不適用，不會是 0）。
- app_code_audit、app_vulns 找 lock file 的時候，或是找 WordPress 外掛的時候，本來要讀的檔案如果不是一般檔案（FIFO、裝置檔，或是 cloud 和 HSM 的 placeholder，例如還沒下載到磁碟上的 OneDrive 檔），現在會寫出來，不再默默跳過：稽核的 `not_checked` 和 app_vulns 的 `partial` 會算出數量，並列出前三個；外掛裡這種 `.php` 檔，在找不到外掛資訊時會列進沒有讀到的項目。link 照舊不會跟過去，也不算在內。
- 連到這台主機以外的模型時，如果連線被拒絕，Windows 上現在也會寫「connection refused」。以前在 Windows 上會寫成「connection failed」，因為 Windows 回的是 WSAECONNREFUSED。
- sudo 的 risk 文字現在用檔案、對象、執行什麼和以哪個帳號執行來寫每一條規則（例如 `/etc/sudoers.d/90-admins: %admin (every command, as root)`），不再直接引用規則那一行，所以送出的文字不會再被遮成 `[REDACTED]`。指令參數或 runas 清單裡的密碼，只要是用 `key=value` 或下面那幾種寫法，在組文字時就先遮掉，所以 survey 自己的輸出（onboard 和存下來的 profile）也不會留著。
- 密碼的遮罩（fixture、log、交給模型的內容，以及 Windows checks 的 command line）現在也會遮掉直接寫在指令參數裡的密碼：mysql 系列程式（`mysql`、`mysqldump`、`mysqlcheck`、`mysqladmin`、`mysqlbinlog` 等，以及 `mariadb` 和它的工具，不分大小寫，也包含 `.exe`）後面的 `-p<密碼>`、用空白隔開寫在 `--password` 或 `--passwd` 後面的密碼，以及 curl、wget 的 `-u user:<密碼>` 和 `--user user:<密碼>`；寫在同一行 JSON argv 裡的也會遮（`["mysqladmin","ping","-p<密碼>"]`、`"--password", "<密碼>"`、`"-u", "user:<密碼>"`，docker inspect 和 healthcheck 就是這樣寫）。`key=value` 的寫法以前就會遮。行程的 command line（`/proc`、`ps`、Windows 的）是一個參數一個參數分開遮，所以密碼裡的 `;`、`|` 或 `&` 會跟著一起遮掉；其他文字（log、shell 的指令紀錄）裡，一個指令只算到沒有引號的 `;`、`|` 或 `&` 為止，所以後面接的 git refspec（`git push -u main:main`）或 `tar -pcf` 不會遮。`-P 3306`、`docker run -p 8080:80`、`mysqld` 和 `mariadbd` 這類 daemon 的 `-port=`、`--password-file=/path`，以及單獨一個、後面沒有值的 `-p`，都不會遮。
- 主機盤點改成直接解析指令輸出的原文，不再先遮（套件和 rpm vendor、防火牆規則、macOS 的平台、帳號、行程、listener、pf 和保護機制）：某個行程的路徑或 iptables 規則的 comment 裡有沒有結尾的私鑰標記時，後面的行程或規則不會再被一起遮掉。解析時用原文，存下來的欄位都有遮，訊息裡引用的指令錯誤文字也會先遮；nginx 和 PHP 的套件查詢照樣讀遮過的文字（那是套件管理程式的輸出）。
- 挖礦程式的檢查（Linux、macOS、Windows）改成比對行程原本的 command line：改了名字的挖礦程式，就算參數寫在一個會被整段遮掉的密碼後面（`mysql -p' -o stratum+tcp://… '`），也找得到。它的證據和交給模型的內容照樣是遮過的。
- 攻擊偵測讀 PHP 的 error log 和 journald 的訊息時，改成直接讀原文，不再先遮：請求裡被回寫到 PHP 位置前面的文字（例如沒有結尾的私鑰標記），不會再把位置一起遮掉，sink 的 error log 證據就留得住。解析出來的事件只留時間和位置，裡面的內容都不會輸出。
- Windows 的 log_search 改成先遮欄位的值，再把名稱和值一起遮一次：值的第一個字是程式名稱時（`CommandLine=mysql -u root -p<密碼>`）也會遮；只把「名稱=值」一起遮的話，前面的 `=` 會讓程式名稱認不出來。
- Windows 的檢查改成直接讀服務的 command line、登錄檔字串和排程工作 XML 的原文，不再先遮：服務路徑、使用者的 home 路徑或排程工作說明裡有沒有結尾的私鑰標記時，不會再藏住沒加引號的服務路徑、啟動資料夾或那個排程工作。輸出的內容照樣是遮過的。
- 網站首頁：捲動時才出現的區塊（統計、開放原始碼、最新版本和河道），從中段進入頁面時（例如從連到頁內位置的連結、回到上一頁，或直接跳到中段）不再一直空白。區塊只要有任何一部分看得到就會出現；頁面一打開就看得到的區塊，以及從頁內位置打開的頁面上的每個區塊，都會立刻出現。
- PHP 規則會追蹤參數不是寫在程式裡的 array 的 `extract()`。`extract($args)`、`extract($_POST)`，或 `extract(wp_parse_args($atts, [...]))`（`$atts` 的每個 key 都會保留）之後，函式裡的每個變數都可能是那份輸入，直到再被指派為止：包括之前定義過的（樣板載入函式的 `$template_name` 會被 `extract($args)` 改寫），以及從沒指派過的（`extract($opts)` 之後的 `$team_id`）。以前一個變數都不會設定，所以 shortcode 的屬性經過這種寫法進到 `include` 或 `call_user_func()` 時不會回報（CVE-2023-6996）。`extract(shortcode_atts($defaults, $atts))` 只會設定 `$defaults` 的 key，也不會改寫 `$defaults` 本身；`EXTR_SKIP` 和 `EXTR_PREFIX_*` 不會改寫任何變數；`extract()` 設定的值，讀它的屬性（`global $wpdb` 之後的 `$wpdb->prefix`）不算輸入，讀它的索引仍然算。flag 照 PHP 的讀法：`EXTR_SKIP` 和 `EXTR_PREFIX_SAME` 不會改寫任何變數，`EXTR_IF_EXISTS` 會改寫但不建立變數，`EXTR_PREFIX_ALL` 和 `EXTR_PREFIX_IF_EXISTS` 只設定名稱以 `prefix_` 起始的變數（prefix 不是寫在程式裡時，任何這種名稱都算）。`extract()` 在 closure 外面新建的變數，closure 只透過它的 `use (...)` 看得到，它的參數是呼叫端給的值。
- PHP 規則：`preg_match($p, $s, $m)`、`preg_match_all()`、`parse_str($q, $out)` 或 `exec($c, $output)` 之後，傳進去被寫入的變數是這個呼叫設定的值，之前 `extract()` 設在那裡的值就不算了；它是否帶有 subject 的輸入，仍然不追蹤；但被寫入的變數就是 subject 本身時（`preg_match($p, $m, $m)`、`parse_str($q, $q)`），它保留原本的值。`catch (E $e)` 的變數是例外物件，不是這個名稱之前的值。
- PHP 規則：WordPress 的 `$wpdb` 存在屬性裡（`$this->wpdb = $wpdb`、`$this->db = &$wpdb`、`self::$mysqli =& $wpdb`），同一個檔案透過它查詢時（`$this->wpdb->get_results(...)`），現在就當成 `$wpdb`，所以把 request 輸入接進這種查詢會回報；以前只有 `$wpdb` 本身算 sink。這個 class（或它 use 的、同一個檔案裡的 trait）要看得到這個指派：只是屬性叫 `wpdb` 或 `db`、在別的檔案（例如上層類別的建構式）設定的，或是同一個檔案裡另一個 class 的同名屬性，都不算 `$wpdb`。
- PHP 規則：request 輸入透過 `$wpdb->prepare()` 傳給寫在反引號裡的 `%s`（這時值是欄位或資料表名稱，有編號的 `%2$s` 也一樣）時，現在會回報（`php-sqli-prepare-identifier`）：`prepare()` 把值當字串加上引號，擋不住欄位或資料表名稱。以前 `prepare()` 一律當成每個值都已處理。放在引號裡、單獨出現、在 `ORDER BY` 後面或 `LIMIT` 裡的 `%s`，以及 `%d` 和 `%i`，都不會回報。
- PHP 規則：放進 `array(...)` 再傳給別的函式的輸入，現在和 `[...]` 一樣保留下來（`edit_status(array($_REQUEST['id']))`）；以前 `array(...)` 被當成引擎不認得的呼叫，輸入不會跟進那個函式的 sink。
- Python 規則：Tornado 的 request 參數（`self.get_argument()`、`self.get_query_argument()`、`self.get_body_argument()`）傳給 `self.redirect()` 時會回報；以前轉址規則不讀這些參數，也不讀 `self.redirect()`。
- PHP 規則：PSR-7 的 request 輸入（`$request->getQueryParams()`、`->getParsedBody()`）傳給轉址回應（`new RedirectResponse($url)`）時會回報。
- PHP 規則：Symfony request 的 body（`$request->getContent()`、`$request->toArray()`）在同一個函式裡寫進 SQL 時會回報，當成 ORDER BY 欄位也會。
- PHP 規則：用 `fgetcsv()` 讀出的欄位（例如使用者上傳的 CSV 檔）沒加 `['allowed_classes' => false]` 就傳給 `unserialize()` 時會回報。
- 新的 JavaScript 規則 `js-file-upload-client-name-write`：上傳的檔案用 `fs.createWriteStream()`、`fs.writeFile()`、`fs.writeFileSync()` 或 `fs.promises.writeFile()`，以用戶端送來的名稱（multer 的 `file.originalname`）寫入時會回報。express-fileupload 的 `.name` 不在範圍內。
- route 模型可以指定註冊呼叫的 hook 名稱（`hooks`）：第一個參數必須是其中一個名稱、而且直接寫成一個字串，這個呼叫才算數；寫成變數、常數或串接字串的都不算。`path` 和 `hooks` 不能同時使用。
- PHP 規則：Elementor 傳給 `elementor/editor/after_save` callback 的第二個參數（存檔時頁面上每個區塊和 widget 的設定，contributor 以上的角色就能寫入）現在當成 request 輸入。以前從這裡的 widget 設定讀出網址再去抓取（`getimagesize()`）時，不會回報。
- cvebench 預設改用和 app_code_audit 相同的掃描方式（`-scanpath product`）：先逐檔掃描，再追蹤跨檔呼叫，兩者的結果合併。以前它直接用跨檔呼叫來判斷每條流向（`Project.Scan`，現在是 `-scanpath project`），所以檢查寫在另一個檔案時，結果會被拿掉，但 app_code_audit 仍然會顯示。規則沒有改變；bench 的修正版誤報通常會變多，數字更接近使用者實際看到的（用 v0.5.8 的案例量測，結果是少報 0）。報告最前面會寫明掃描方式和專案的上限。
- bench：比較用的基準改用和 app_code_audit 相同的掃描方式（`-scanpath product`）重新量測（cves 是 `baseline.md`，另外新增 `baseline-holdout.md`、`baseline-cves-ts.md`）；先前的基準是第一次量測，只有 59 案，逐檔掃描。
- `php-nosqli-mongo-query`，以及 CodeIgniter、Doctrine、Drupal、Joomla、Yii 的 SQL 規則：從別的檔案接過去的 method sink（`$Db->find(...)`、`->where(...)`），如果專案自己的類別有宣告同名的方法，而且 app_code_audit 讀到的內容都沒有提到那個函式庫（PHP 程式、字串、composer.json、composer.lock，以及 vendor/ 裡的套件名稱；vendor/ 的檔案本身不讀），就不再回報：那是專案自己的方法（例如 WordPress plugin 自己寫的 SQL 類別）。以前任何物件上的同名方法都算。只要有一處提到那個函式庫、專案沒有宣告這個方法，或 app_code_audit 有跳過檔案（跳過的資料夾例如 node_modules/、.git/，超過 8 層的資料夾，大於 1 MiB 或讀不到的規則語言檔案，超過 20,000 個檔案，或掃描沒有跑完），仍然會回報；在同一個檔案裡找到的呼叫也照樣回報。
- `php-deserialization-wp-maybe-unserialize`：每條路徑上都是 array 的參數不再回報（`maybe_unserialize(array('fields' => $_POST['f']))`、用 key 寫入的 array、`explode()` 的結果），由程式自己的函式把參數原樣傳過去時也一樣：`maybe_unserialize()` 只會 unserialize 字串，array 會原樣傳回。以前 array 裡的輸入照樣算數。取出 array 裡的一個值、由它組成的字串，以及有一條路徑給的是字串，仍然會回報。程式可能用引擎看不到的方式改寫的 array 也照樣回報：最上層（不在任何函式裡）或宣告成 `global` 的變數、檔案裡有 `$$name`、`${...}` 或 `$GLOBALS`，或整個傳給 method、算出來的函式、會用 `&` 接收參數的 PHP 函式、專案沒有宣告的函式（WordPress 本身的函式只有少數已知不用 `&` 接收參數的除外），或專案裡用 `&` 接收參數的函式。

- 規則：函式 sink 的 `[[args]]` 可以指定哪個參數是 handle（`handle`，要和 `receiver` 一起用）。這樣 `fwrite($fp, ...)` 只有在 `$fp` 是 `receiver` 列的函式（例如 `fsockopen()`）產生的時候才算數：直接寫在呼叫裡、同一個函式裡這次呼叫之前最近的一次指派，或者 `$this->fp` 在同一個函式裡沒有指派過時，同一個 class 檔案裡其他地方的指派。看不出來源的 handle 不算：參數、`STDOUT`、方法的回傳值、在別的方法設定的 static 屬性、`$s[0]` 這種寫法，或 `foreach` 的變數；`list()` 會把等號後面的整個值給每一個目標，所以會多報。一個檔案的屬性指派超過 4096 筆時，這個檔案就不追（掃描會記下截斷原因 `handle-table`）。沒有規則用到時不會多做任何事；目前還沒有規則用到它。
- 新的規則類別 `crlf`（CWE-93、CWE-77）：把換行寫進網路連線上送出的一行指令。第一條規則是 `php-crlf-socket-write`：request 輸入用 `fwrite()` 或 `fputs()` 寫進 socket（`fsockopen()`、`stream_socket_client()` 產生的，透過 `handle` 條件判斷），當成 IMAP 指令或 HTTP 請求行送出時會回報。寫進一般檔案、或來源不明的 handle 不回報。用 `header()` 設定的回應 header 不屬於這一類。
### 已知問題

- 直接寫在指令參數裡的密碼，下面幾種情況不會遮：密碼全是 JSON 標點（`, : { } [ ]` 和空白）；密碼裡空白之後的部分（command line 是用空白把 argv 接起來的；在 shell 指令行裡加了引號的會整段遮掉）；log 或 shell 的指令紀錄裡，沒有引號的 `;`、`|`、`&` 之後的部分；分成多行寫出的 JSON argv，或前面的字串裡有 `]` 的 JSON argv；以及其他程式的密碼參數（`sshpass -p`、`redis-cli -a`、`ldapsearch -w`、`smbclient -U user%<密碼>`、`mongosh -p`、`htpasswd -b`、curl 的 `--pass` 和 `-E cert:<密碼>`）。
- 有些檢查讀進來的文字仍然是先遮過的：Windows 的 event data（每一欄各自遮；log_search 裡的事件文字也是一欄一欄分開遮）。
- 事件裡密碼的名稱和值如果分在兩個欄位（名稱在一欄、值在下一欄），在 log_search 的文字裡不會被遮；Windows 內建的事件沒有這種寫法（CommandLine、ImagePath、ScriptBlockText 都是單一欄位）。
- 一般文字裡（log、shell 的指令紀錄、cron），如果 `mysql` 是傳給參數的使用者名稱（`--user mysql -p5432`、`psql -U mysql -p5432`），會被當成程式名稱，後面的 `-p` 也會被遮掉；行程的 command line 是一個參數一個參數判斷的，不會這樣。檔名結尾是 `.mysql` 時（`psql -f backup.mysql -p5432`），一般文字和行程的 command line 都會這樣多遮。
- log_search 比對的是遮過的文字，被遮罩遮住的內容找不到。如果改成比對原文，從每一次有沒有比對到，就能一點一點試出被遮掉的密碼。
- 錄下來的 fixture 只存遮過的文字，所以用 fixture 重放時，檢查的判斷可能和在主機上直接跑不一樣：例如參數被遮罩遮住的挖礦程式，以及攻擊偵測拿到的 error log 證據可能比較少（error log 或 journald 訊息裡的位置被遮罩遮住時）。
- 轉址目標的檢查寫在另一個檔案時（例如 Tornado base class 的 `self.sanitize_next_url()`），仍然會回報：app_code_audit 先逐檔讀，跨檔追蹤看到檢查之後，那筆結果也不會拿掉。
- `js-file-upload-client-name-write` 不會把 allowlist 當成檢查：檔名結尾或 MIME 類型已經對照清單檢查過，再用用戶端的名稱寫入時，仍然會回報（express-cart 1.1.7）。
- 值交給路由產生器、產生站內路徑時（例如 PSR-7 的 `urlFor()`、Flarum 的 `$url->to(...)->route()`、Tornado 的 `reverse_url()`），轉址仍然會回報。
- `fgetcsv()`：在 `while` 條件裡指派的列（`while (($row = fgetcsv($h)) !== false)`）不會被追進 `while` 的內容裡，所以這種最常見的 CSV 讀法會漏掉。應用程式自己附的 CSV 檔也會回報。
- 用資料庫函式庫的 `->escape()` 處理過、放在引號裡的值，仍然會回報（`php-sqli-string-concat`）：有些函式庫的 escape 不會加引號，數字的位置也擋不住，所以規則不把 `->escape(` 當成檢查。現在 Symfony 的 body 也會流到這裡。
- 用 `json_decode()` 解開的 Symfony body 傳給別的函式時，輸入會在那裡斷掉，所以在 controller 解開、在另一個類別寫進 SQL 的欄位會漏掉。
- 對輸入 `extract()` 之後，它設定的變數讀屬性（`$cfg->path`）不算輸入，因為 request 資料只會設定字串和 array。`extract((array) json_decode($in))` 和 `extract(get_object_vars(json_decode($in)))` 可能設定物件，它的屬性是輸入，這兩種會漏報。
- `reference` 規則有幾種寫法判斷不準：指令其實整行寫在程式裡，但拆成幾個中間沒有 `+` 的字串（`os.system('ls ' '-l')`，Python 會自動接成一個），或用 `' '.join()` 接起全是字面值的串列，仍然會報；屬性形式的物件（`h.env.from_string(s)`）只看名稱判斷，就算檔案裡寫了 `h.env = Engine()` 也一樣；`import os as o` 之後的 `o.system(cmd)`，以及換了名稱 import 的函式（`from hashlib import md5 as m` 之後的 `m(x)`），不會報。
- 在非 Windows 的機器上 replay Windows 主機的記錄時，code audit 的 ASP 檢查、web root 的 ACL 檢查，以及不分大小寫的路徑比對，都還沒有打開，app_vulns 和 app_code_audit 的 path 參數，除非和某個 app path 完全相同，否則會被拒絕（v0.5.9 處理）。
- route 模型只在註冊它的那個檔案裡找 handler：`elementor/editor/after_save` 的 callback 如果寫在另一個檔案（hook 寫在外掛主檔、函式寫在 include 裡），就不會被當成 handler，那裡的抓取也不會回報。其他 route 模型也有同樣的限制。
- `php-crlf-socket-write` 追不到 Roundcube 的 IMAP 指令（CVE-2026-126813）：id 經過應用程式自己的輸入函式讀進來，再透過存在屬性裡的物件、跨多個類別的方法呼叫才寫進 socket。建構子存進屬性、由另一個方法寫出去的輸入也追不到。用 `$` 結尾、只放行英文和數字的白名單會被當成檢查，但結尾的換行仍然可以通過。

## v0.5.7 — 2026-11-26

- PHP 規則會讀 `filter_input()`。用 `filter_input(INPUT_GET, ...)`、`INPUT_POST` 或 `INPUT_COOKIE` 取得的值，以及應用程式自己同名的方法（`->filterInput(`、`->filter_input(`）在第一個參數是這幾個常數時取得的值，在每一條會讀 `$_GET`、`$_POST` 或 `$_COOKIE` 的 PHP 規則裡都算請求輸入。第一個參數是變數或其他常數（例如 `INPUT_SERVER`）時不算。數字或 bool 的 filter（`FILTER_VALIDATE_INT`、`FILTER_VALIDATE_BOOL`、`FILTER_SANITIZE_NUMBER_INT` 等，寫成具名參數 `filter:` 也一樣）取得的值不帶輸入，但用 `|` 加上 flag 時不算（`FILTER_VALIDATE_INT | FILTER_NULL_ON_FAILURE` 是另一個 filter ID，PHP 7 會當成 `FILTER_DEFAULT`）；`FILTER_SANITIZE_SPECIAL_CHARS` 在把 `htmlspecialchars()` 當清理函式的規則裡算清理過；URL 的 filter 不算清理。
- macOS：netstat 給的 pid 是 0 的 listening socket，看不出是哪個程序，所以 listening port 的清單會標成部分（partial），並寫明有幾個，不再當成每個 owner 都知道的完整清單。
- PHP 規則認得應用程式自己寫的 guard 函式。一個函式如果只有在檢查過路徑參數之後才回傳 true（白名單，例如 Welcart 的 `usces_is_reserved_file()`，或是 `realpath($p)` 加上 `strpos($real, $base) === 0`），在它回傳 true 的地方（`if (guard($f)) { ... }`，或 `if (!guard($f)) { die(); }` 之後），傳進去的值就算清理過；寫成別的 class 的方法也一樣。guard 裡改寫了參數、在檢查前就回傳 true，或只檢查檔案存在的，都不算。路徑規則把 `strpos(`、`stripos(` 和 `=== 0` 或 `!== 0` 的比較，當成檢查路徑起始的比對，而且只檢查第一個參數（`strpos('/var/logs/', $real)` 在 `/` 和 `/var` 時也成立）。`realpath($p)` 找到檔案的地方，對伺服器端請求和 phar 規則來說，`$p` 不再是 URL 或 `phar://` wrapper；路徑規則照樣回報。用 `in_array()` 查 `basename($p)` 或 `intval($id)`，不再算驗證了 `$p` 或 `$id`：`../../x/log.txt` 和 `1 OR 1` 都會通過這種查表。
- `shentu patrol --dry-run` 顯示的所有標題（每一組攻擊紀錄、超過單輪上限的合併通知、攻擊偵測的通知）都改用設定的語言，和實際送出的通知一樣；之前一律是英文。
- 修正 v0.5.6 的已知問題：`new $var(...)` 不再被當成呼叫參數 `$var`。它是用 `$var` 指的類別建立物件，並沒有呼叫 callable；大寫的 `NEW $var(...)` 也一樣。在這個位置傳入變數的呼叫端，不再被標成「呼叫沒有全部追完」，參數帶的輸入也不再被當成流到函式的回傳值，因此不會再出現這類誤報（`echo get_entity($_GET['a'], $c)` 原本會回報 `php-xss-echo-html`）。附帶 Freemius SDK（`fs_get_entity($entity, $class)`）的外掛，這種檔案最多。
- block_ip 的登入索引讀大量登入紀錄時，改用做的事較少的讀法，結果和完整讀取相同。索引滿的時候，720 小時內沒有事件的位址最多每一小時（以事件時間計）清掉一次，不再每碰到一個沒有位置的位址的事件就清一次。只有字串欄位的 journal 行改用平面的讀法，讀出的欄位和完整讀法相同；其他的行照舊交給完整讀法。巡檢讀到時間用完時，會先存下讀到的部分再接著讀，直到讀到結尾或用掉 15 分鐘，所以兩次巡檢之間的檢查只要讀新進來的部分。可能在索引的 65,536 個位址之外的位址，仍然一律拒絕，不會放行。
- 巡檢改成在其他檢查、通知和攻擊偵測的通知都送出之後，才追登入索引。有大量登入紀錄時，追索引最多要 15 分鐘，這一輪的通知不必再等它。
- block_ip 的登入索引改用 journal 裡的序號（cursor 的 `s=` 和 `i=`）分辨時間相同的紀錄。之前 vacuum 刪掉一筆和留下的第一筆時間相同的紀錄時，索引會把刪掉的那筆當成還在：位址被刪掉的事件會被當成 sshd 自己寫的，但整段讀取看不到任何紀錄；被刪掉的偽造事件也仍然會拒絕封鎖。不知道序號時（舊版存的索引、格式不對的 cursor、重建的 journal），改用時間判斷，並一律取比較嚴格的判斷：會拒絕封鎖的紀錄，時間和第一筆相同也算還在；會放行的事件，時間相同就不算。
- 網站的發版河道：每個版本的說明框在任何頁面大小下都留在河道裡（原本在 844px 時頁面會多捲動 3px）；燈下的文字（版本、日期、規則數）只在放得下時顯示，最新版和 x.y.0 優先，沒有顯示的在指標移到燈上或用鍵盤選到燈時會出現（原本在 844px 和 1440px 燈下的文字都會擋到下一盞燈的文字）；每盞燈的連結會讀出版本、日期、規則數和 bench 結果。
- 程式碼稽核改成依做了多少工作停下，不再依時間：每個檔案的第一輪和整個專案的呼叫追蹤各有工作量上限（60M 和 1.5G），時鐘只留作安全上限。追到哪裡、回報什麼，不再取決於機器快慢或負載高低；慢的機器會花更多時間跑完，不會提前停下。在 WordPress 7.1.4（2,148 個 PHP 檔）上，沒跑完的檔案從每次都不一樣的約 800 到 1,100 個，變成每次都是 16 個，記憶體沒有上升。
- `app_vulns` 和每日巡檢會檢查 site-packages 裡已安裝的 Python 套件（app 路徑下的 venv、`/usr/local/lib/python3*`，以及 `/usr/lib/python3*` 裡由 pip 安裝的套件），和 lock 檔一樣用 PyPI 比對 OSV，並標出 CISA KEV。之前只讀 lock 檔，用 pip 安裝、但沒有寫在任何 lock 檔裡的套件不會被檢查。掃描有上限（往下 8 層、100 個 site-packages 資料夾、每個資料夾 5,000 個套件、每個 METADATA 只讀前 64 KiB，不跟隨 symlink），超過上限或讀不到的部分會在報告裡寫成沒有檢查。
- 也會列出那些資料夾裡，含有每次啟動 Python 都會執行的行的 `.pth` 檔：只寫檔案和這種行有幾行，不寫內容。要能證明是工具（setuptools、virtualenv、editable install）自己寫的，才會標成是那個工具的：每一行都完全符合，工具自己的紀錄也在（列出這個檔案本身和它的模組、記有 sha256 的 RECORD、`pyvenv.cfg` 裡 virtualenv 的 key，或系統套件管理的資料夾），而且資料夾、上面每一層資料夾和這些檔案都只有 root 能寫。在一般使用者也能寫的資料夾裡，寫得了 .pth 的人也寫得了那些紀錄，所以 setuptools、virtualenv 和 editable install 的檔案會在每日報告裡列為無法證明；其他的由巡檢以 warning 送出通知。
- PHP 在 `<script>` 內容裡的 XSS：放在 JS 引號字串裡、用 `esc_attr()`、`esc_url()`、`esc_html()` 或 `htmlspecialchars(..., ENT_QUOTES)` 處理過的值（`var tab = '<?php echo esc_attr($_GET['tab']); ?>';`），如果 PHP 區塊後面的文字在同一行把這個字串關起來，就不再回報：`<script>` 內容不會解碼 entity，兩種引號和 `<` 都編碼過，值就留在字串裡。以下情況照樣回報：`on*` 屬性（會先解碼 entity）、template literal、前面的區塊寫出引號或反斜線、行尾用 `\` 接到下一行、`htmlspecialchars()` 沒有 `ENT_QUOTES`，以及 `sanitize_text_field()`。
- PHP 的伺服器端請求規則把「本機路徑起始」當成固定的起始：目錄常數接著帶有路徑段的字串（`WP_CONTENT_DIR . '/uploads/' . $name`，或例如 Welcart 先存進變數），或是磁碟機（`'C:\\data\\' . $name`）。這時輸入選不了 scheme 或 host，所以讀這種路徑的 `file_get_contents()` 不再被回報為伺服器端請求；路徑規則照樣回報。常數包括 `__DIR__`、`DIRECTORY_SEPARATOR`，以及 WordPress、Drupal、Joomla 的目錄常數（`ABSPATH`、`WP_CONTENT_DIR`、`DRUPAL_ROOT`、`JPATH_ROOT` 等）。以下照樣回報：外掛自己的常數、用輸入定義的常數（就算是上面這些名稱也一樣，例如 `define('ABSPATH', $_GET['b'])`）、常數後面只接 `/` 或 `/a`、只有磁碟機的 `C:`、以 `\\` 起始，以及字串裡有 `\x3a` 這類 escape。
- SQL injection 和 XSS 規則把計算的結果當成數字，數字不會帶引號或標記：放進 `LIMIT` 的分頁 offset `(max($_GET['paged'], 1) - 1) * 20`（例如 Welcart）、PHP 的 `$_GET['n'] + 1`、JavaScript 的 `req.query.n - 1`，以及 Python 的 `request.args['n'] - 1`，在這些規則裡都不再回報。計算指 `-`、`/`、`*`、`%` 和 `**`，PHP 再加上前後有數字的 `+`；Python 是 `//`、`**`，以及前後有數字的 `-` 或 `/`。以下仍算輸入：PHP 兩個 array 的 `+`（把兩個 array 合起來）、兩個字串的 `|`、和 `-` 一起用的 `.`、JavaScript 的二元 `+`、Python 的 `*`（會重複字串）、Python 兩個 set 或兩個 `Counter` 的 `-`（兩者的差集，例如 `set(request.args.getlist('id')) - {'0'}`），以及路徑規則裡的數字。
- 套件弱點檢查（`vulns`）會把第三方的 PHP 和 nginx 套件（來自 deb.sury.org、ondrej PPA、Remi 的套件庫或 nginx.org）和 php.net、nginx.org 2026-11-19 的版本比對，用的是 PHP 和 nginx 檢查的同一份表格。OSV 只收發行版自己的公告，所以這些套件在 OSV 裡什麼都對不到，以前只會列在 `third_party_unchecked`。現在套件版本範圍內的每個 CVE 都會列進弱點面（ecosystem 是 `upstream:php` 或 `upstream:nginx`，附上修正版本，CISA KEV 有列出的會標示 KEV），也列在 `third_party_upstream`，並計入 `total_vulns` 和 `affected_packages`，同一個來源套件的同一個 CVE 只算一次，和 OSV 的結果一起算；CISA KEV 有列出的也會放進 `actively_exploited`（一筆，列出受影響的二進位套件），所以每日巡檢會和發行版的套件一樣送出 critical 的 KEV 告警。套件的 changelog 已經列出的 CVE（backport 的修正）列為 backported，不回報。php-fpm 另外加上 FPM 和狀態頁的 CVE，php-cgi 加上 CGI 的 CVE；mod_php 和 CLI 只比對引擎本身的 CVE。每個比對過的套件都會寫出表格的日期（`as_of`）。讀不到版本、php.net 已經不再修正的分支，或比表格裡最新的版本還新（例如 PHP 8.3.38、9.0，或 nginx 1.32），套件仍然列在 `third_party_unchecked`，原因寫在 `why`。這些套件的 OSV 結果照樣保留，因為套件也可能比發行版的修正還舊。

### 已知問題

- 從資料庫讀回來的值，如果讀它的查詢用了輸入，即使已經用 escape 函式處理過，也會被當成輸入（例如 `$row = $db->LoadSingle("... '" . mysqli_real_escape_string($c, $_POST['id']) . "'")` 之後，把 `$row['tag']` 放進另一個查詢）：引擎把不認得的函式的回傳值，當成帶有參數的輸入。YesWiki 的 despam.php 就是這樣被回報的。
- 應用程式自己產生同站網址的函式（YesWiki 的 `$this->wiki->Href('', $name)`、`href()`）不會被認出來，所以導向到這種網址也會被回報為 open redirect（YesWiki 的 LoginAction.php、DuplicateHandler.php）。
- macOS 27 上，由 ad-hoc 簽章的程式（release binary 就是）啟動的程序，netstat 看不到 Internet socket：`netstat -anv` 什麼都不輸出（exit 0）。這時 shentu 改用 lsof 列出 listening port，但 lsof 只看得到同一個使用者的程序，所以清單會標成部分。在 Terminal 裡直接跑 netstat 就看得到。macOS 15 沒有這個問題。
- 用 `apt-mark hold` 鎖住的 Debian 或 Ubuntu 套件（dpkg 狀態是 `hi`）不會被檢查：套件清單只收狀態是 `ii` 的套件，所以 `vulns`、每日巡檢和弱點面都看不到它，也不會列為未檢查。下一版會修正。

## v0.5.6 — 2026-11-24

- 沒跑完的檔案會說明是被什麼截斷的（#172）。程式碼稽核列出的未完成檔案多了 `cause`：token 上限、單一檔案的時間上限、巢狀層數超過上限、規則追呼叫的工作量上限、專案的上限（時間、記憶體或 token）、可能呼叫到別的檔案但沒有唯一對象可追的呼叫，或被呼叫函式的 summary 被截斷（並寫出原因：它自己的工作量上限、summary 一層接一層超過上限、參數超過上限，或它裡面另有截斷）。CVE bench 開始計入「呼叫沒有全部追完」的檔案（以前沒算），並依原因列出截斷數。

- PHP 的 sink 和清理函式，函式名稱與方法名稱改成不分大小寫比對，和 PHP 實際呼叫時一樣（#189）。`System($_GET['x'])`、`SYSTEM(...)`、`\SYSTEM(...)`、命名空間裡的 `System(...)`，以及被呼叫函式裡的 `Shell_Exec($c)`，現在都和小寫寫法一樣會回報；寫成 `EscapeShellArg($x)` 的清理函式也會生效。名稱也叫 `system` 的方法（`$o->System(...)`、`Task::SYSTEM(...)`）仍然不算 sink。JavaScript 和 Python 的名稱照舊分大小寫。字串裡用兩個反斜線寫的內建函式名稱（`array_map('\\system', $x)`、`"\\system"`），PHP 讀到的是 `\system`，現在也照內建函式處理。指向 PHP 內建函式的 pattern，不會再對上用 `new` 建立的類別（`new File($p)`、`new System(...)`），也不會對上命名空間裡的函式（`Storage\file($p)`，以及有宣告 namespace 的檔案裡的 `namespace\file($p)`）；以前小寫的 `new file(` 和 `A\file(` 會被對上。`\file($p)` 仍然是內建函式。成員 pattern 的方法名稱和類別名稱也改成不分大小寫比對（#198）：`$wpdb->Query(...)`、`$wpdb->GET_RESULTS(...)` 是 `php-sqli-wpdb-unprepared` 的 sink，`$wpdb->Prepare(...)` 會清理，`DB::RAW(...)` 也是 sink；變數名稱照舊分大小寫（`$WPDB` 不是 `$wpdb`）。

- 透過 callable 的呼叫會追下去（#182、#184、#188）。PHP 函式呼叫自己的參數時（`$cb($v)`，例如 `tap()`、`Arr::first()`），會在每個呼叫它的地方，用呼叫端傳進來的值追下去：closure、函式名稱（`'run_cmd'`、`'Cmd::run'`）、array 寫法的 callable（`[Cmd::class, 'run']`、`[$this, 'run']`），或 first-class callable（`run_cmd(...)`）。交給 PHP 內建函式呼叫的 closure（`array_map`、`array_filter`、`array_walk`、`usort`、`array_reduce`、`preg_replace_callback`、`call_user_func` 等），會用內建函式傳給它的輸入去分析；callable 寫成內建函式的名稱時，就是那個內建函式：`array_map('system', $_GET['x'])` 和 `array_map(function ($v) { system($v); }, $_GET['a'])` 現在都會回報。呼叫沒有追完的檔案也變少了（#174、#178、#179、#182）：Python 的標準函式庫 import（套件裡另有自己的 `json.py` 時的 `import json`），和離不開所在函式的 closure，不再被當成專案裡其他檔案的呼叫對象。在 E7 的語料上，laravel-framework 沒跑完的檔案從 280 個變成 115 個，Django 從 135 個變成 24 個。

- 檢查和固定的值造成的誤報變少了（#185、#187）。`unset($x)`、`unset($a['k'])`、`unset($this->p)` 之後，值不再帶有輸入；`is_numeric`、`is_int`、`is_float`、`ctype_digit` 這類數字檢查在每條規則裡都算檢查（`if (is_numeric($p)) { ... "WHERE id = " . $p }` 不再回報）。`wp_create_nonce()` 和 `wp_hash()` 的回傳值不帶輸入。呼叫端先做過 `check_admin_referer()` 這類 nonce 檢查，再呼叫的函式裡的 sink，和直接寫在呼叫端的 sink 一樣處理；需要輸入出現在最前面的 sink（`header("Location: $u")`），參數最前面是固定文字時（`go(admin_url('x') . '?a=' . $v)`），經過函式也不算到達。

- 主機盤點加上 PHP 版本檢查，對照 php.net 2026-11-19 的版本（8.2.36、8.3.37、8.4.28、8.5.13；8.6.0 以後都已修正）。版本是每個 PHP 執行檔自己寫在檔案裡的版本（`php`、`php-fpm`、`php-cgi` 和帶版本號的名稱，在各發行版的位置、Docker 的 PHP image 用的 `/usr/local`、Remi 的 `/opt/remi`、cPanel 的 `/opt/cpanel/ea-php*`，以及 CloudLinux 的 `/opt/alt/php*`），直接讀檔案，不執行它；Windows 上是 IIS 用 FastCGI 執行的 `php-cgi.exe`。套件掃描看不到的 PHP 這樣也查得到：deb.sury.org、ondrej PPA、Remi 的套件庫、vendor 不是發行版的 rpm（IUS、cPanel）、Docker image、從原始碼 build 的，以及 IIS。執行檔寫了不只一個版本、程式裡找不到版本，或 FastCGI 的路徑不是本機的絕對路徑時，會列為無法檢查。和 nginx 的檢查一樣，套件的 changelog 已列出某個 CVE 時，不會為它警告。CVE-2026-129291 和 CVE-2026-129289 只有 php-fpm 在執行時才警告；CVE-2026-129292（狀態頁）只有 pool 的 `pm.status_path` 從外面連得到時才警告，也就是它的 socket 接受其他主機的連線，或 nginx（server 不是只 listen 127.0.0.1）、Apache 把這個路徑轉給 FPM，而且沒有用 `deny all` 或 `Require local` 限制。每個分支只讀自己的 pool；設定檔的 include 會跟著讀，註解不算。CVE-2026-129538 只有 php-cgi 在執行，或 IIS 會執行它時才警告。其餘 14 個依版本合成一行。php.net 已經不再修正的分支（8.2 以前）只有不是發行版套件時才列出；讀不到的資料（行程清單、設定檔、IIS 的設定）會列在一行說明裡，指出哪幾項無法檢查。

- Windows 上，主機盤點和每日的弱點面會找出 Apache 以 CGI 執行的 php-cgi.exe（讀 httpd.conf 和它 Include 的檔案，包括 XAMPP 的 `httpd-xampp.conf`：`ScriptAlias` 指到 php-cgi.exe 或它所在的資料夾、`Action` 透過這種 alias 指到它，或那個資料夾設了 `AddHandler cgi-script .exe`），檢查 CVE-2024-4577（8.1.29、8.2.20、8.3.8 修正）和它的 bypass CVE-2024-8926（8.1.30、8.2.24、8.3.12 修正）。是否受影響由系統字碼頁（ACP）決定：CVE-2024-4577 是 932、936 或 950，CVE-2024-8926 是 ANSI 字碼頁被設成 OEM 字碼頁；讀不到字碼頁時用 warning 回報，並註明「字碼頁未確認」。8.1 以前的分支公告沒有列出、也不會修正，用 warning 回報。弱點面只有在 CISA KEV 目錄列出時才標示 KEV。IIS 上的 php-cgi.exe 不為這兩個 CVE 回報，因為公告只寫到 Apache，版本那一行會寫明。Apache 只認服務執行的那一個，以及 XAMPP、Apache Lounge 的固定位置（只有在 httpd.conf 只有系統管理員能寫入時才讀）；設定檔裡的網路路徑或裝置路徑（`\\host\share`）一律不讀，被 Include 的檔案如果是指到這種路徑的 link，也不讀。讀到的設定裡沒有用 `LoadModule` 載入 cgi_module 或 cgid_module 時，Apache 不會執行 CGI，所以用 warning 回報，不是 critical；寫在 `<IfModule>` 裡的也當作已載入。如果有設定檔沒讀到，仍然用 critical 回報，並寫明有設定未讀。路徑上的 link 無法檢查，或是路徑在 `C:` 之後還有 `:` 或 `?`（例如 ADS）時，也不讀。

- 攻擊偵測新增 CVE-2024-4577 的簽章（#199）：在 `.php` 檔（後面有沒有 PATH_INFO 都算）、網站首頁（`/`）或 `/php-cgi/php-cgi.exe` 的查詢字串裡送出 php-cgi 的命令列參數（軟連字號 `%AD` 或 `%C2%AD` 後面接一個英文字的參數，或連字號後面接單獨一個英文字的參數）。這條簽章依 CVE 對應到主機，所以只在 surface 裡有 CVE-2024-4577 的主機上發出告警，並帶上該項目的 KEV 標示；其他主機上的命中只算雜訊。

- 巡檢自己的檢查找到的項目，在 `language` 設定是中文時也改用中文：新開的連接埠、不正常的程序、UID 0 的帳號、authorized_keys 的變動、
  連結和共用的金鑰、ld.so.preload、PAM 模組、webshell、憑證、SSH 登入失敗、CISA KEV 漏洞，以及 authorized_keys 裡讀不懂的行。
  英文文字和之前逐字相同，交給 AI 模型的仍是英文清單。來自工具的項目（伺服器設定的風險、和上次相比的設定變動、程式碼稽核）目前仍是英文。

- 套件弱點檢查（`vulns`）會列出不是從發行版套件庫安裝的套件，放在 `third_party_unchecked`，並寫明來自哪個套件庫、用什麼方式認出來的。OSV 只收發行版自己的套件，所以這些套件原本是被當成發行版的套件去比對，結果什麼都對不到；這種「沒有結果」不等於「沒有弱點」。認出的方式有三種：版本號（deb.sury.org 的 `+deb.sury.org`、nginx.org 的 `-N~codename`）、第三方 apt 套件庫的索引，以及不是發行版的 rpm vendor。第三方套件庫（apt，以及 Alpine 的 main、community、testing 以外的套件庫）會列在 `third_party_repositories`；設定了第三方套件庫，但分不出哪些套件來自它時，會加一行說明。只有 `Packages`、沒有 `Release` 的套件庫（flat repo）算第三方。rpm vendor 只有在它自己的發行版上才算發行版的套件（Rocky 上的 Oracle MySQL 套件算第三方）。讀不到的索引，以及被截斷的 rpm vendor 輸出，會列在 `origin_unread`。Origin、vendor 和套件庫路徑都是發布套件庫的人自己寫的，第三方套件庫如果用發行版的名稱，就會被當成發行版：這個檢查只能把套件多列出來，不能證明套件是發行版的。

- block_ip 檢查一個位址的 SSH 登入時，不再每次都讀一個月的 journal。sshd 那幾個 unit（ssh、sshd，以及 socket 啟動的 ssh@、sshd@）的登入紀錄，會按位址記在 state 目錄的 `loginindex.json`（權限 0600，整份寫完再換上）；每次檢查和每小時的巡檢，都從上次讀到的 journal cursor 接著讀。
  判斷規則不變：一個位址在時間範圍內（最近一天有紀錄就看最近一天，否則看 720 小時）的每一筆紀錄，都要是 sshd 自己寫的（`_COMM` 是 sshd 或 sshd-session，`_UID` 是 0），才算數；journald 裡沒有紀錄的位址，照舊去讀文字 log。
  在 VM 上一份 1,200,000 筆的 journal，原本一次檢查要讀大約 37 秒。

- 整段讀取不放行的封鎖，索引也不會放行；整段讀取看不到的紀錄，也不會讓索引多擋。沒有索引時（第一次執行，或檔案是舊的格式），從 720 小時前開始讀；索引沒有讀到的時間範圍，照舊整段讀取。
  每次讀取也會查 sshd 的 unit 現在從 journal 的哪一筆開始：在那之前的紀錄（被清理，或被攻擊者大量寫入而輪替掉）不再算數。cursor 那一筆已經不在時，journalctl 不會報錯，而是從最近的一筆開始讀：索引從 cursor 那一筆讀起，發現它不在了，就從還在的第一筆（含這一筆）接著讀，並記下一筆紀錄。
  每一筆紀錄最多讀到 1 MiB，和整段讀取相同，所以 user 名稱有 70 KB 的紀錄，照樣算在它的位址上；只有超過這個長度、整段讀取也讀不了的紀錄，才會讓包含它的時間範圍一律算成無法驗證。
  讀到一半時間用完，已經讀到的部分會保留，下一次接著讀，所以被大量寫入的 journal 會在幾次檢查之間讀完，每一次都不超過時限。
  位址超過 65,536 個時，其他位址的紀錄合在一起計算；可能在其中的位址一律不放行封鎖。存下的 cursor 格式不對，或是位址的內容是 null，讀索引時會直接不用。

- 按下 ✅ 後檢查來不及做完時，改成以「來不及檢查」（`timeout`）拒絕，不再說成「紀錄讀不到」（`state_error`）。

### 已知問題

- Windows 上只有 Apache 以 CGI 執行的 php-cgi.exe 會把 CVE-2024-4577 寫進 surface（#200）。IIS 用 FastCGI 執行的 php-cgi.exe 不寫，因為公告只寫到 Apache；Shentu 不讀的 Apache 設定也不寫，也就是不是服務執行的、不在 XAMPP 或 Apache Lounge 的固定位置，或是有一般使用者能寫入的。這些主機上，這條簽章的命中仍然只算雜訊。

- 在 surface 有 CVE-2024-4577 的主機上，沒有 `=`、只有一個字的查詢，如果最前面是不是 UTF-8 的位元組再接一個英文字（沒有用 UTF-8 送出的 Latin-1、Big5 或 Shift-JIS 字），會和 `%AD` 一樣比中 CVE-2024-4577 的特徵：請求是解碼後才比對，這類位元組都會讀成 U+FFFD（`docs/attack-detection-limits.zh-TW.md`）。

- `new $var(...)` 會被當成呼叫參數 `$var`（#182）。附帶 Freemius SDK 的外掛會有大量「呼叫沒有全部追完」的檔案，也可能因此出現誤報；在 E7 和 CVE bench 的量測中沒有少報。將在 v0.5.7 修正。

## v0.5.5 — 2026-11-23

- 預算接近上限時，進行中派遣已經用掉的部分不再重複計算：預留會記下它屬於哪一次派遣、何時開始，其他派遣只算它剩下的部分，
  而且和本月用量在同一次讀取 log 時算出。對不起來的預留照舊整筆計算。

- survey（site_profile）現在和它的其他讀取一樣，經由主機來源檢查 Docker 和 Podman 的 socket：
  replay 或 fixture 不會再讀到執行 survey 的那台機器。

- nginx 和 Apache 的版本檢查（以及 nginx 的 changelog）現在和其他檢查一樣，經由主機來源讀取受檢主機：
  replay 或 fixture 不會再讀到執行檢查的那台機器。套件查詢都是 allowlist 裡的完整指令。

- macOS：`listening_ports`、`processes`（以及巡檢的程序檢查）現在讀取 Mac 本身（netstat 或 lsof，以及 ps；不需要 root），
  不再讀 Linux 的 /proc。以前在 Mac 上什麼都讀不到，結果和一台什麼都沒在執行的主機一樣。讀不到時會回報錯誤，只讀到一部分也會寫明。

- macOS：`accounts_audit` 現在讀取 Mac 的帳號（dscl；不需要 root）、可登入帳號和 root 的 authorized_keys，
  sudoers 讀得到時也會讀。讀不到的部分寫在 note；Linux 才有的檢查（ld.so.preload、不是套件安裝的 PAM 模組）會列為不適用。

- macOS：`file_changes` 現在依檔案的狀態變更時間（ctime）找出異動，改過修改時間也藏不住，並附上擁有者名稱；
  預設檢查 macOS 自己的位置（/private/etc、Homebrew、launchd 的 job），讀不到的目錄會列出來。`cert_expiry` 也會讀 Homebrew 的 certbot。

- macOS：`ssh_logins`（以及巡檢的 SSH 檢查）現在從 unified log 讀取 sshd 的登入紀錄（`/usr/bin/log show --info --style ndjson`），計數方式和 Linux 相同，並標為 verified（已驗證）：只算 sshd-session 或 sshd 本身程式路徑、而且由 root 記下（userID 0）的紀錄。
  這兩點已在 macOS 15 的 VM 上確認：有人把程式複製到 /tmp 並取同樣的名字，記下的是它自己的路徑；使用者用自己的設定執行系統的 sshd，記下的是那個使用者的 ID，不是 0。
  沒有算進來的紀錄，會在結果的 source 寫明筆數和原因（`not_logged_by_root`、`not_sshd_image`、`no_user_id`、`unreadable_event`）。
  紀錄沒有 userID 或讀不懂，或是輸出缺少 log show 最後的結束行時，結果會標成不完整（算到的次數只是下限），不會當成完整但次數較少的結果。
  這份 log 只有 root 和 admin 群組讀得到；其他帳號會得到寫明原因的權限錯誤，不會回空結果。

- macOS：`log_search` 預設讀取 macOS 的文字 log（system.log、install.log）。Homebrew 的 nginx 和 Apache log 不在預設裡，因為這些目錄屬於一般使用者，可以在裡面建連結指到 root 的檔案；要讀的話請自己加進設定。
  放在 /var 的 log 現在可以用 log_paths 寫的路徑讀取（macOS 的 /var 是連到 /private/var 的連結，以前這種路徑會被拒絕）。有一個以上 hard link 的 log 檔會被拒讀，因為連到 log 目錄的 root 專用檔案看起來也是這樣。
  sshd 的紀錄在 unified log 裡，log_search 不讀那裡，工具說明會寫明：在這些檔案裡找不到，不等於沒有 SSH 登入。

- 主機盤點的 nginx 檢查補上 nginx 2026-11-18 公告的其餘項目（#190）。CVE-2026-118899 是透過 TLS 1.3 讀取 request body 時會一直重複、不會停下的問題：nginx 1.13.0～1.31.8 有 TLS 的 server（`listen ... ssl`，或 `ssl on`）會用 TLS 1.3 時就警告，也就是對它生效的 `ssl_protocols`（它自己的，否則是 http 區塊的）列了 `TLSv1.3`，或是沒有設定 `ssl_protocols` 而 nginx 是 1.23.4 以後的版本，預設就包含 TLS 1.3。關掉 HTTP/2 也沒有用。CVE-2026-113425 是 mail proxy 的 use-after-free，只有 `mail` 區塊裡有 server 時才警告。其餘 6 個中低風險項目（resolver、HTTP/3、用用戶端憑證或 `ssl_preread` 的 stream、`try_files` 加上 `alias`、PROXY protocol v2）依版本合成一行建議，因為這項檢查不看這些功能的設定。全部都在 1.31.9 和 1.30.7 修正。和 HTTP/2 的檢查一樣，套件的 changelog 已列出某個 CVE 時，不會為它警告；讀不到的設定檔會列在一行說明裡，指出哪幾項無法檢查。

- 每日報告和新發現報告現在依照 `language` 設定：設定是中文時，標題、各段標題和固定的說明文字（沒檢查到的項目、漏洞檢查沒做完、攻擊偵測、
  子 Agent 派遣、自動事件調查、SSH 登入）都改用中文；v0.5.4 以前不管 `language` 怎麼設，這些都是英文。檢查找到的內容、錯誤訊息和
  AI 模型寫的回答不會改寫，照原樣附上。

- macOS 和 Windows（#206）：`block_ip` 在任何檢查之前就以 `unsupported` 拒絕。之前在 macOS 上從 Telegram 呼叫時，會先讀最多一個月的 unified log（大約兩分鐘）才拒絕，而 nftables 在這兩個平台上本來就不能封鎖。

- 提案按鈕（Linux，#206）：送出按鈕前的檢查，全部加起來在 90 秒內結束；到時還沒查完的提案列為 `timeout`，不給按鈕，其他提案的按鈕照常送出。派遣存檔的檢查因時限到了而中斷時，也記成 `timeout`，不再是 `state_error`。同一個位址的 SSH 登入，存檔、送按鈕和 Telegram 的事前檢查只讀一次（結果在兩分鐘內沿用）；`block_ip` 真正執行時仍會重新讀。

- 升級須知（#206）：裝回 v0.5.4 時，舊版會把 gate 是 `timeout` 或 `unsupported` 的派遣紀錄當成壞行，自動事件調查最多會停 72 小時。

## v0.5.4 — 2026-11-23

- 共用 AI 預算（#161）：bot、`shentu chat` 與自動事件調查的每次派遣，執行期間會在 `state_dir/reservations.json`
  預留它整份 token 上限，每一道預算檢查都會把其他派遣的預留算進去，所以合計超出 `[budget] monthly_tokens`
  約一個派遣的上限（12 萬 tokens），再加上進行中的那一個回答。升級須知：派遣進行中時，別處的提問可能會被告知「其他派遣的預留讓本月剩餘預算不夠」
  （預留最多約 17 分鐘就會釋放）；預留檔不可信時，所有 AI 回答與派遣都會停下，直到把檔案移開（bot 會指出要移開哪個檔案）；`auto_incident` 開啟而
  `monthly_tokens` 不超過 150000 時，現在會發出警告，因為那樣自動調查永遠不會啟動。

- 模型價格（#162）：`[agents] price_per_mtok_in` 與 `price_per_mtok_out`（每一 M tokens 的價格，以 USD 計）會用來替每次派遣的預留估價：
  token 上限依兩者中較高的價格計算，所以每月金額上限也和 token 上限一樣由各派遣共用。只有金額上限被其他派遣的預留填滿時，
  回覆會寫出預留的金額。

- `shentu usage` 與 bot 的 /usage 現在會計入子 Agent 的模型呼叫（以及其他來源的呼叫）（#164）：
  以前這些呼叫沒有算進總數；派遣的呼叫現在另列一行。

- `auto_incident` 開啟但沒有設 `[notify] url` 時，現在會發出警告（#165），時機是 bot 啟動、每日巡檢與它的報告：
  自動調查只會從巡檢推送出去的 L3 告警開始，而巡檢只經由 notify url 推送，所以一次也不會啟動。

- 建議按鈕按下後，如果 bot 在檢查過程中或等待確認時被停止，log 會記成 bot 已停止（#166），不再記成被拒絕或操作者沒有確認。

- `shentu dispatch stats --json` 現在有固定版本的格式，供每 7 天的彙整使用：除了天數、計數、角色和建議之外，多了 `v`（1）、`shentu`（版本）、
  `until`（UTC 日期），角色和建議一律是清單。內容只有數字和固定字詞，不含主機名稱、位址、路徑、派遣 id 或 trigger。

- 同一個呼叫被兩條規則回報時，就算檔案裡的某個呼叫只有其中一條規則會追，也照樣只留下被讓的那條（`yields_to`）（#160）。以前 `DB::select(DB::raw("..." . $_GET['a'] . "..." . col()))` 這種寫法，如果本地的 `col()` 回傳 `get_query_var('o')`（只有 php-sqli-orderby-identifier 讀這個輸入），會同時被 php-sqli-laravel-raw 和 php-sqli-orderby-identifier 回報；讓給 php-sqli-yii-query 的那幾條規則也有同樣的問題。

- JavaScript 的 request 別名（#160）：`if`/`else` 之後，一個名稱的值取自「會繼續執行下去的分支」結尾時的值。所以每個分支都重新指定過的名稱（`let q = req; if (a) { q = {...} } else { q = {...} }`）不再當成 request。return 或 throw 的分支不算；以 `break` 或 `continue` 結尾的分支照樣算。

- URL 檢查保留的唯讀呼叫（#160）：`typeof window`（`typeof` 後面接 `window`、`globalThis` 這類物件）不會再讓整個檔案的唯讀呼叫失效。條件運算式裡 `:` 後面的 `String`（`const S = c ? y : String;`）現在會讓它失效，和把 `String` 當成值來用一樣；以前它被當成 TypeScript 的型別。

- PHP：如果檔案的 `use` 讓 `Request` 指向別的函式庫的類別（`use Httpful\Request`、`use Unirest\Request`、`use Httpful\Http as Request`），`Request::get(` 不再當成 Laravel 的 request facade（#160）。

- 派遣紀錄可以讀有不認得欄位的行（#197）：從 v0.5.4 起，之後的版本加了新欄位寫下的紀錄或回饋，這一版照樣會讀，認得的欄位照舊逐一檢查，不再整行當成讀不到（以前這會讓自動事件調查停到執行 repair 為止）。這種行會在 `shentu dispatch stats`（JSON 是 `unknown_field_lines`）和每日報告裡另外計數；`repair` 不會移動這些行；不認得的欄位內容不會出現在任何輸出。

- 升級須知：裝回 v0.5.4 以前的版本後，v0.5.4 寫下、帶有沒查到項目（`unchecked_why`）的派遣紀錄，舊版讀不到。這些紀錄的建議按鈕會回答派遣紀錄裡沒有這次派遣；`shentu dispatch stats` 會把這些紀錄當成讀不到的行跳過；自動事件調查會因為派遣紀錄有讀不到的行而停止，直到執行 `sudo shentu dispatch repair`，把這些行移到 `*.jsonl.bad`（保留，不會刪除），之後從下一輪巡邏起重新計數。

- 通知改用 `language` 設定的語言（v0.5.3 真 bot 驗收的 F-1、F-4）：自動事件調查、「Approved from Telegram」、配對與解除配對，以及攻擊偵測通知的標題，以前不管設定都是英文；現在 `language` 是中文時改用中文，和 bot 自己的訊息一樣。自動事件調查的通知用一般的說法寫出找到幾項，沒有建議時直接寫「這次沒有建議任何動作」。沒查到的項目只用固定字詞說明，子 Agent 寫的內容照舊不放進通知：子 Agent 現在要寫出是哪個工具，並從 `tool_failed`、`permission_denied`、`not_applicable`、`time_limit` 裡選原因（其他值一律算「其他」），程式另外會加上 `not_available` 和 `findings_cut`，派遣紀錄也會保存（`unchecked_why`）；子 Agent 選的原因在通知裡會標明是子 Agent 回報、未經確認；沒有固定字詞的項目只列數量，請當成「不知道」。確認後的通知先說會發生什麼事（「開始封鎖 192.0.2.30，24 小時後自動解除；是否成功以 bot 的回覆為準」），nft 指令改放在後面。每日報告和新發現報告裡的固定文字還是英文。

- 子 Agent 的建議會留下紀錄（F-3）：可以提出建議的子 Agent 每次回報都會在 log 記一筆 `proposals`（寫了幾項、留下幾項），每一項被拿掉的建議都用固定字詞記下原因：`ip_is_a_network`、`ip_not_one_address`、`action_not_propose_block_ip`、`duplicate_ip`、`too_many_proposals`、`role_cannot_propose`（只列前 20 項，也只記形狀：網段記成標準寫法，其他只留位址會用到的字元；另外記總數；派遣紀錄本身的上限記在 `proposals_cut`）。以前建議被拿掉和根本沒有建議，看起來是一樣的。現在會要求可以提出建議的子 Agent：只對證據明確的位址提出建議（已驗證攻擊群組裡的位址，或已驗證的 SSH 紀錄裡失敗很多次的位址），不要從 header 這類紀錄文字取位址；一個建議只放一個位址，不能放網段。自動事件調查也會向子 Agent 說明，這次的起因是一則已驗證的 L3 警報，而且這則警報的位址會排在最前面；重複的位址不再佔名額。建議仍然只是一顆按鈕：閘門和按下後的檢查都沒有改。

## v0.5.3 — 2026-11-22

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
- `shentu usage` 沒有算進自動調查子 agent（`sub:incident`）的模型呼叫：測試機上 log 有 13 次，usage 只列 9 次；`shentu budget` 有算進去。修正（#164）排在 v0.5.4。
- 自動調查的通知和「Approved from Telegram」通知不論 `language` 設什麼都是英文。

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
