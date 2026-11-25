package main

// The fixed words of the patrol's reports (the daily report and the new
// findings report), in the configured language as the notices are: they
// go out through notify url to the same chat as the bot's own messages.
// Error text and the model's answer are not translated; the checks'
// summaries are, where they are made (newFinding), except those of
// package tools (v0.5.5 PR-B, C).

var dailyText = map[string][2]string{ // English, Chinese
	"title_daily":   {"Daily security report", "每日資安報告"},
	"title_new":     {"%d new finding(s)", "%d 項新發現"},
	"llm_down":      {"(LLM unavailable: %v)", "（AI 模型無法使用：%v）"},
	"findings_head": {"\n\nFindings:\n", "\n\n發現：\n"},
	"findings_more": {"- (%d more finding(s), less severe, not listed: the next patrols send them; shentu chat lists them all)\n", "- （另外 %d 項較不嚴重的發現沒有列出：之後的巡邏會送出；shentu chat 可以看到全部）\n"},
	"dry_surface":   {"\nAttack detection: --dry-run does not build the vulnerability surface (surface.json); `shentu patrol --daily` does.\n", "\n攻擊偵測：--dry-run 不會建立漏洞面（surface.json）；`shentu patrol --daily` 才會。\n"},
	"det_err":       {"\nAttack detection: %s\n", "\n攻擊偵測：%s\n"},

	"ssh_failed":  {"\n\nNot checked: SSH logins (%q).\n", "\n\n沒檢查到：SSH 登入（%q）。\n"},
	"ssh_cut":     {"a login log was cut short or could not be read", "有登入紀錄被截斷或讀不到"},
	"ssh_partial": {"\n\nNot checked in full: SSH logins (%q); the failed logins counted are a lower bound%s.\n", "\n\n沒有全部檢查到：SSH 登入（%q）；算到的登入失敗次數只是下限%s。\n"},
	"ssh_root":    {" (run Shentu as root to read every log)", "（用 root 執行神荼才讀得到所有紀錄）"},

	"perm_head":  {"\n\nNot checked (the permission to read what they need was missing; run Shentu %s):\n", "\n\n沒檢查到（缺少讀取所需檔案的權限；請%s執行神荼）：\n"},
	"perm_root":  {"as root", "用 root "},
	"perm_win":   {"elevated, as the Shentu service does (LocalSystem)", "用系統管理員身分（和神荼服務一樣用 LocalSystem）"},
	"audit_head": {"\n\nNot checked by the code audit:\n", "\n\n程式碼稽核沒檢查到的部分：\n"},
	"conf_head":  {"\n\nWeb server configuration not read (its web roots are missing from the code audit):\n", "\n\n讀不到的網頁伺服器設定（它的網站根目錄不在程式碼稽核裡）：\n"},

	"vuln_os":           {"installed packages", "已安裝的套件"},
	"vuln_app":          {"application dependencies", "應用程式相依套件"},
	"vuln_failed":       {"\n\nNot checked for vulnerabilities: %s (%q)%s.\n", "\n\n沒有檢查漏洞：%s（%q）%s。\n"},
	"vuln_dns":          {"; the name lookup failed: check this host's DNS (the resolver in /etc/resolv.conf) against `getent hosts %s`", "；網域名稱查詢失敗：請用 `getent hosts %s` 檢查這台主機的 DNS（/etc/resolv.conf 裡的解析器）"},
	"vuln_partly":       {"- partly checked: %q", "- 只查了一部分：%q"},
	"vuln_nokev":        {"- not checked against the CISA KEV list, so exploited ones are not marked: %q", "- 沒有比對 CISA KEV 清單，所以正在被利用的漏洞沒有標出來：%q"},
	"vuln_kevleft":      {"- %d vulnerabilities not checked against the CISA KEV list (lookups failed or over the cap)", "- 有 %d 個漏洞沒有比對 CISA KEV 清單（查詢失敗或超過上限）"},
	"vuln_file":         {"- not checked (%q): %s", "- 沒檢查（%q）：%s"},
	"vuln_filemore":     {" and %d more", "（另外 %d 個）"},
	"vuln_otherfiles":   {"- and %d more lock files not checked, with other errors", "- 另外還有 %d 個 lock 檔因為其他錯誤沒檢查"},
	"vuln_noeco":        {"- not queried (OSV has no such ecosystem): %q", "- 沒有查詢（OSV 沒有這個套件生態系）：%q"},
	"pth_unproven":      {"\n\n%d .pth file(s) look like a tool's own (setuptools, virtualenv, an editable install), in folders a user can write, so that cannot be proven; they run code at every Python start:\n", "\n\n%d 個 `.pth` 看起來是工具自己寫的（`setuptools`、`virtualenv`、`editable install`），但在一般使用者也能寫的資料夾裡，無法證明；它們會在每次啟動 Python 時執行：\n"},
	"pth_unproven_more": {"- and %d more", "- 另外還有 %d 個"},
	"vuln_head":         {"\n\nVulnerability check of %s incomplete:\n", "\n\n%s的漏洞檢查沒有做完：\n"},

	"det_head":     {"\nAttack detection:\n", "\n攻擊偵測：\n"},
	"det_levels":   {"- groups seen in the last day: L3 %d, L2 %d, L1 %d (reached a vulnerable route only: counted, not pushed), undetermined %d\n", "- 過去一天看到的攻擊組：L3 %d、L2 %d、L1 %d（只打到有漏洞的路由：只計數，不推送）、無法判定 %d\n"},
	"det_due":      {"- alerts due this round: %d (pushed on their own after this report, at most %d one by one, the rest in one summary); noise %d, unanchored %d, undetermined (cut) %d\n", "- 這一輪要發的警報：%d 則（在這份報告之後另外推送，最多 %d 則逐一發送，其餘合成一則摘要）；雜訊 %d、對不到漏洞面 %d、無法判定（中途截斷）%d\n"},
	"det_report":   {"- report (addresses masked): %s\n", "- 報告（位址已遮蔽）：%s\n"},
	"det_notcheck": {"- not checked: %s\n", "- 沒檢查到：%s\n"},
	"det_plugins":  {"\nAttack detection: WordPress plugin directories not read:\n", "\n攻擊偵測：讀不到的 WordPress 外掛目錄：\n"},
	"det_more":     {"- (%d more)\n", "- （另外 %d 個）\n"},
	"det_nosave":   {"\nAttack detection: the vulnerability surface could not be saved: %s\n", "\n攻擊偵測：漏洞面沒能存檔：%s\n"},

	"disp_unread":   {"\nSub-agent dispatches: the archive could not be read (%s)\n", "\n子 Agent 派遣：讀不到派遣紀錄（%s）\n"},
	"disp_head":     {"\nSub-agent dispatches (last day; reports are the model's, not verified):\n", "\n子 Agent 派遣（過去一天；報告由 AI 撰寫，未經查證）：\n"},
	"disp_count":    {"- %d dispatches: %s; %s\n", "- 派遣 %d 次：%s；%s\n"},
	"disp_external": {"- %d used the sub-agents' model outside this host ([agents] base_url): masked logs and settings were sent to it\n", "- 其中 %d 次用的是這台主機以外的子 Agent 模型（[agents] base_url）：遮蔽過的日誌和設定送到了那裡\n"},
	"disp_subs":     {"- sub-agents: %s\n", "- 子 Agent：%s\n"},
	"disp_why":      {"- why incomplete: %s\n", "- 沒有完成的原因：%s\n"},
	"disp_props":    {"- proposed blocks (suggestions, not actions): %s", "- 建議封鎖（只是建議，沒有執行）：%s"},
	"disp_prop":     {"%s (gate %s)", "%s（閘門 %s）"},
	"disp_nogate":   {"not checked", "沒檢查"},
	"disp_propmore": {", and %d more", "，另外 %d 個"},
	"disp_bad":      {"- %d archive lines could not be read and were skipped\n", "- 有 %d 行派遣紀錄讀不到，已跳過\n"},
	"disp_extra":    {"- archive lines with fields this version does not know: %d (read; those fields are ignored)\n", "- 派遣紀錄裡有這個版本不認得的欄位：%d 行（照常讀入，不認得的欄位略過）\n"},
	"disp_repaired": {"- `shentu dispatch repair` ran %d times: %d unreadable archive lines moved out (%d of them new to *.jsonl.bad), %d empty lines dropped (%s)\n", "- `shentu dispatch repair` 執行了 %d 次：移出 %d 行讀不到的派遣紀錄（其中 %d 行是新放進 *.jsonl.bad 的），刪掉 %d 行空白行（%s）\n"},

	"auto_head":       {"\nAutomatic incident checks (L3 alerts, read-only, last day):\n", "\n自動事件調查（L3 警報，只讀不改，過去一天）：\n"},
	"auto_nobudget":   {"- none are made: no monthly token budget is set ([budget] monthly_tokens; monthly_cost alone does not stop a local model, which reports no cost)\n", "- 一次都不會做：沒有設定每月 token 預算（[budget] monthly_tokens；只設 monthly_cost 擋不住本機模型，因為本機模型不回報費用）\n"},
	"auto_longlines":  {"- log.jsonl lines longer than %d KiB skipped when adding up the month's AI use: %d\n", "- 加總本月 AI 用量時，略過超過 %d KiB 的 log.jsonl 行：%d 行\n"},
	"auto_nostate":    {"- not known: %s could not be read (%s)\n", "- 不知道：讀不到 %s（%s）\n"},
	"auto_count":      {"- dispatched: %d of at most %d (not complete: %d)\n", "- 已派遣：%d 次（上限 %d 次；沒有完成：%d 次）\n"},
	"auto_unfinished": {"- unfinished: %d (a slot was taken but the dispatch never ended: shentu stopped during it; the slot still counts)\n", "- 沒有結束：%d 次（已經占用名額，但派遣一直沒有結束：神荼在派遣途中停了；名額仍然算數）\n"},
	"auto_notsaved":   {"- not saved to the dispatch archive: %d (the slot still counts; see the audit log)\n", "- 沒存進派遣紀錄：%d 次（名額仍然算數；請看稽核日誌）\n"},
	"auto_skipped":    {"- not dispatched: %s\n", "- 沒有派遣：%s\n"},
	"auto_useunknown": {"- the month's AI use could not be read (log.jsonl): none were made\n", "- 讀不到本月的 AI 用量（log.jsonl）：一次都沒做\n"},
	"auto_platform":   {"- automatic incident checks run on Linux only for now: none were made, and no daily slot was used\n", "- 自動事件調查目前只在 Linux 上執行：一次都沒做，也沒有占用今天的名額\n"},
	"auto_budgetstop": {"- the month's AI budget reached %d%%: automatic checks stopped until next month\n", "- 本月 AI 預算已用到 %d%%：自動調查暫停到下個月\n"},
	"auto_pending":    {"- waiting for a later round: %d\n", "- 等之後的輪次：%d 個\n"},
	"auto_untrusted":  {"- stopped: the dispatch archive (%s) cannot be trusted (%s); none are made until its owner and mode are fixed (0700, files 0600, this service's user)\n", "- 已停止：派遣紀錄（%s）不可信（%s）；在修好擁有者和權限之前（目錄 0700、檔案 0600、擁有者是這個服務的使用者）一次都不會做\n"},
	"auto_badlines":   {"- stopped: %d lines of the dispatch archive could not be read (the newest in %s); none are made until that file leaves the count at %s (at most 72 hours), or sooner after %s (it moves them to *.jsonl.bad in %s)\n", "- 已停止：派遣紀錄有 %d 行讀不到（最新的在 %s）；要等到 %s 那個檔案不再算進來（最多 72 小時）才會恢復，或執行 %s 之後提早恢復（它會把那些行移到 %s 裡的 *.jsonl.bad）\n"},
	"auto_nonotify":   {"auto_incident is on, but no [notify] url is set: a check starts only from an L3 alert the patrol pushed, and the patrol pushes through the notify url alone, so none will start and nothing would be sent. Set [notify] url (for Telegram telegram://<bot-token>@telegram?chats=<chat id>, the bot's own token works; or a Slack or Discord webhook), for example with `sudo shentu setup`", "auto_incident 已開啟，但沒有設定 [notify] url：自動調查只會從巡邏推送出去的 L3 警報開始，而巡邏只透過 notify url 推送，所以一次都不會開始，也不會送出任何東西。請設定 [notify] url（Telegram 可以寫 telegram://<bot-token>@telegram?chats=<chat id>，用 bot 自己的 token 就可以；也可以用 Slack 或 Discord 的 webhook），例如執行 `sudo shentu setup`"},
	"auto_lowbudget":  {"auto_incident is on, but [budget] monthly_tokens = %d is not more than %d: an automatic check reserves %d tokens and starts only while that stays under %.0f%% of the limit, so none will ever start; raise monthly_tokens to more than %d", "auto_incident 已開啟，但 [budget] monthly_tokens = %d 沒有大於 %d：每次自動調查會先保留 %d tokens，而且只有保留後仍低於上限的 %.0f%% 才會開始，所以一次都不會開始；請把 monthly_tokens 調到大於 %d"},
	// Finding summaries (the checks' own, in package main); the English
	// column is the summary as it was before (TestFindingTextEnglish).
	"f_ssh":           {"%d failed SSH logins from %s in the last hour (successful logins: %d)%s", "過去一小時有 %d 次來自 %s 的 SSH 登入失敗（成功登入：%d 次）%s"},
	"f_ssh_text":      {"; read from text logs, which anyone on this host can write to: check them before acting", "；這是從文字紀錄讀到的，這台主機上任何人都能寫入，採取行動前請先確認"},
	"f_unparsed":      {"%s line(s) %s%s are neither a key nor a comment; sshd ignores them, but check none is a key written in another form", "%s 有幾行既不是金鑰也不是註解（第 %s 行%s）；sshd 會略過這些行，但請確認其中沒有用其他格式寫的金鑰"},
	"f_unparsed_more": {" and %d more (%d in all)", "，另外 %d 行，共 %d 行"},
	"f_port":          {"new listening port %s by %s (%s)", "新的監聽埠 %s，由 %s（%s）開啟"},
	"f_proc":          {"suspicious process pid %d (%s): %s", "可疑程序 pid %d（%s）：%s"},
	"f_uid0":          {"account with UID 0 besides root: %s", "除了 root 之外，還有 UID 0 的帳號：%s"},
	"f_keys":          {"authorized_keys changed: %s (%d keys)", "authorized_keys 有變動：%s（%d 把金鑰）"},
	"f_keylink":       {"%s links to %s, outside the home; sshd reads the keys there (%d keys), check who can write that file", "%s 連結到家目錄以外的 %s；sshd 會讀那裡的金鑰（%d 把），請確認誰能寫入那個檔案"},
	"f_sharedkey":     {"one SSH key (%s) is in the authorized_keys of %s; attackers plant one key in every account, check that it is yours", "同一把 SSH 金鑰（%s）出現在 %s 的 authorized_keys 裡；攻擊者常在每個帳號放同一把金鑰，請確認這是你的"},
	"f_preload":       {"/etc/ld.so.preload loads %s into every program, a common rootkit trick; check each library with dpkg -S or rpm -qf and verify it with dpkg -V or rpm -V", "/etc/ld.so.preload 會把 %s 載入每個程式，這是常見的 rootkit 手法；請用 dpkg -S 或 rpm -qf 查出每個函式庫屬於哪個套件，再用 dpkg -V 或 rpm -V 驗證"},
	"f_pam":           {"PAM module %s was not installed by a package; a PAM backdoor can let anyone log in by SSH; check it with dpkg -S or rpm -qf %s", "PAM 模組 %s 不是套件安裝的；PAM 後門可以讓任何人用 SSH 登入；請用 dpkg -S 或 rpm -qf %s 檢查"},
	"f_webshell":      {"possible webshell: %s", "可能是 webshell：%s"},
	"f_cert":          {"certificate for %s expires in %d days", "%s 的憑證再 %d 天就到期"},
	"f_kev_os":        {"%s %s has %s, which is being exploited in the wild (%s); update it: %v", "%s %s 有 %s，這個漏洞正在被實際利用（%s）；請更新：%v"},
	"f_kev_app":       {"%s pins %s %s, which has %s, exploited in the wild (%s); upgrade it", "%s 鎖定了 %s %s，它有 %s，正在被實際利用（%s）；請升級"},
	"f_kev_site":      {"%s has %s %s installed, which has %s, exploited in the wild (%s); upgrade it", "%s 安裝了 %s %s，它有 %s，正在被實際利用（%s）；請升級"},
	"f_pth":           {"%s has %d line(s) Python runs at every start, not a known tool's own: check what installed it", "%s 有 %d 行會在每次啟動 Python 時執行，不是已知工具自己寫的：請確認是誰安裝的"},
	"repair_win":      {"`shentu dispatch repair` from an elevated prompt (Run as administrator)", "`shentu dispatch repair`（在以系統管理員身分開啟的命令提示字元）"},
}

func dt(zh bool, key string) string {
	if zh {
		return dailyText[key][1]
	}
	return dailyText[key][0]
}

// Enumerations the reports count by, in Chinese (enumWord keeps the
// fixed word for any other language or value).
var (
	originZh = map[string]string{originChat: "伺服器上的 shentu chat", originTelegram: "Telegram", originAuto: "自動調查"}
	skipZh   = map[string]string{autoSkipNoBudget: "沒設預算", autoSkipBudget: "預算到上限", autoSkipBudgetUnknown: "用量不明", autoSkipDailyCap: "今天次數已滿",
		autoSkipGroup: "同一組已查過", autoSkipUnverified: "日誌不可信", autoSkipOverflow: "來源太分散", autoSkipNoIP: "沒有可用的 IP",
		autoSkipQueueFull: "等待佇列已滿", autoSkipExpired: "等太久已過期", autoSkipArchive: "派遣紀錄讀不到", autoSkipPlatform: "平台不支援"}
)
