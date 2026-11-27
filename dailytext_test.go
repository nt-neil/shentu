package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/tools"
)

var reVerb = regexp.MustCompile(`%[-+# 0-9.]*[a-zA-Z%]`)

// Both columns of every report text take the same arguments in the same
// order: a Chinese line that dropped or swapped one would print another
// value in its place.
func TestDailyTextVerbs(t *testing.T) {
	for k, v := range dailyText {
		if v[0] == "" || v[1] == "" {
			t.Errorf("%s: a column is empty", k)
		}
		if en, zh := reVerb.FindAllString(v[0], -1), reVerb.FindAllString(v[1], -1); !slices.Equal(en, zh) {
			t.Errorf("%s: verbs %v (English) vs %v (Chinese)", k, en, zh)
		}
	}
}

// reportWords are the words a Chinese report keeps in Latin letters:
// names and abbreviations, not sentences. Words that are English only as
// part of a command, a setting or a file name are in reportPhrases, whole.
var reportWords = map[string]bool{
	"Agent": true, "AI": true, "token": true, "tokens": true, "KiB": true, "L1": true, "L2": true, "L3": true, "IP": true,
	"SSH": true, "DNS": true, "CISA": true, "KEV": true, "OSV": true, "root": true, "LocalSystem": true, "Linux": true,
	"WordPress": true, "Python": true, "Docker": true, "Telegram": true, "Slack": true, "Discord": true, "webhook": true, "bot": true,
	"sshd": true, "PAM": true, "UID": true, "pid": true, "rootkit": true, "webshell": true,
}

// reportPhrases are settings, file names and commands said outside a
// `quote` (a quoted one is taken out whole).
var reportPhrases = []string{
	"telegram://<bot-token>@telegram?chats=<chat id>", "[notify] url", "notify url", "[budget] monthly_tokens", "monthly_tokens",
	"monthly_cost", "[agents] base_url", "auto_incident", "--dry-run", "shentu chat", "surface.json", "log.jsonl", "*.jsonl.bad",
	".jsonl", "lock 檔", "authorized_keys", "dpkg -S", "rpm -qf", "dpkg -V", "rpm -V",
}

var (
	reQuoted = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|` + "`[^`]*`")
	reAddr   = regexp.MustCompile(`[0-9a-f]*:[0-9a-f:]*:[0-9a-f:]*(?:/\d+)?`)
	rePath   = regexp.MustCompile(`(?:/[^\s（）()：，；、]*)+`)
	reLatin  = regexp.MustCompile(`[A-Za-z][A-Za-z0-9_]*`)
	// A time's zone abbreviation, whatever the host's zone (JST, CET).
	reZone = regexp.MustCompile(`(\d\d:\d\d) [A-Z][A-Za-z]{1,5}\b`)
)

// latinLeft is each run of Latin letters in s that is not one of
// reportWords, outside quoted values (what a check or a log said), paths,
// addresses, a time's zone and reportPhrases.
func latinLeft(s string) []string {
	s = reZone.ReplaceAllString(reQuoted.ReplaceAllString(s, ""), "$1")
	for _, p := range reportPhrases {
		s = strings.ReplaceAll(s, p, "")
	}
	s = rePath.ReplaceAllString(reAddr.ReplaceAllString(s, ""), "")
	var left []string
	for _, w := range reLatin.FindAllString(s, -1) {
		if !reportWords[w] {
			left = append(left, w)
		}
	}
	return left
}

// englishLeft is what is left in s of English: an English template's own
// fragments, cut at its verbs, as they are, and latinLeft.
func englishLeft(s string) []string {
	var left []string
	for _, v := range dailyText {
		for _, frag := range reVerb.Split(v[0], -1) {
			if frag = strings.TrimSpace(frag); len(frag) >= 12 && strings.Contains(s, frag) {
				left = append(left, frag)
			}
		}
	}
	return append(left, latinLeft(s)...)
}

// S-1: every Chinese text, whether or not a test reaches the line it is
// on, is Chinese: its verbs taken out, no English is left.
func TestDailyTextChineseColumn(t *testing.T) {
	for k, v := range dailyText {
		if left := latinLeft(reVerb.ReplaceAllString(v[1], " ")); len(left) > 0 {
			t.Errorf("%s: English left %q in %q", k, left, v[1])
		}
	}
}

// The report sections the daily patrol adds, built on a Chinese setting
// through every line they can say: none keeps an English sentence.
// (What a check found, error text and the model's answer are data and
// stay as they came; here they are quoted, or are paths.)
func TestDailyReportChinese(t *testing.T) {
	state, _ := filepath.EvalSymlinks(t.TempDir())
	cfg := &Config{StateDir: state, Language: "繁體中文"}
	cfg.Agents.AutoIncident = true
	now := time.Now()

	// The dispatch archive: a record, an incomplete one, a line with a
	// field this version does not know, and one that cannot be read.
	s := newDispatchStore(cfg)
	rec := testRecord(testDispatch, now)
	rec.Subs = append(rec.Subs, subRecord{Role: "attack", Status: statusIncomplete, Reason: reasonTokenCap, Steps: 3})
	rec.Status, rec.External = statusPartial, true
	if err := s.Save(rec); err != nil {
		t.Fatal(err)
	}
	day := filepath.Join(state, dispatchDir, now.Local().Format(time.DateOnly)+".jsonl")
	other := testRecord("0123456789ab", now)
	line, _ := json.Marshal(other)
	line = append(line[:len(line)-1], []byte(`,"zz_later":1}`)...)
	f, err := os.OpenFile(day, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.Write(append(line, '\n'))
	f.WriteString("not a record\n")
	f.Close()
	err = withAutoState(state, now, func(st *autoState) {
		st.Dispatches = append(st.Dispatches, autoSlot{TS: now.Add(-time.Hour)}, autoSlot{TS: now, ID: testDispatch, Status: statusPartial, NotArchived: true})
		for _, k := range autoSkipOrder {
			st.skip(now, k)
		}
		st.Pending = append(st.Pending, autoPending{IP: "203.0.113.9", Trigger: "t"})
	})
	if err != nil {
		t.Fatal(err)
	}

	var parts []string
	parts = append(parts, autoIncidentSection(cfg, now)) // no notify url, no budget, bad archive line
	cfg.Budget.MonthlyTokens = autoMinTokens
	parts = append(parts, autoIncidentSection(cfg, now)) // too small a budget
	if _, _, err := s.Repair(); err != nil {
		t.Fatal(err)
	}
	parts = append(parts, dispatchDaily(cfg, now)) // after the repair: its line
	parts = append(parts, dispatchSection(nil, 0, errors.New("讀取錯誤"), true), autoArchiveLine(&Config{StateDir: filepath.Join(state, "missing", "x")}, now, true))

	risks := []tools.Risk{{Key: "unchecked:shadow", Summary: "/etc/shadow is not readable"}}
	parts = append(parts, uncheckedSection(risks, true), notCheckedSection([]string{"C:\\inetpub ACL"}, true), uncheckedConfigs([]string{"/etc/nginx/nginx.conf"}, true), referenceSection(3, true))
	var files []tools.AppResult
	for i := range uncheckedFiles + 2 {
		files = append(files, tools.AppResult{Path: "/srv/app" + string(rune('a'+i)) + "/package-lock.json", Error: "osv down"})
	}
	files = append(files, tools.AppResult{Path: "/srv/x/go.sum", Error: "e2"})
	for i := range uncheckedErrors {
		files = append(files, tools.AppResult{Path: "/srv/y/go.sum", Error: "e" + string(rune('a'+i))})
	}
	r := map[string]any{"partial": "ALAS cut", "total_vulns": 3, "kev": "unavailable: x", "files": files, "ecosystems_not_queried": []string{"Hex"}}
	parts = append(parts, uncheckedVulns(dt(true, "vuln_app"), r, nil, true))
	parts = append(parts, uncheckedVulns(dt(true, "vuln_os"), map[string]any{"total_vulns": 2, "kev_unchecked": 2}, nil, true))
	parts = append(parts, uncheckedVulns(dt(true, "vuln_os"), nil, &net.DNSError{Name: "osv.dev", Err: "no such host"}, true))

	ds := detectSummary{Due: 2, ReportPath: "/var/lib/shentu/detect/report.txt", Err: "偵測錯誤"}
	ds.Levels = map[string]int{"L3": 1}
	parts = append(parts, detectSection(ds, true))

	_, why := sshFindings(nil, errors.New("journal"), 5, true)
	parts = append(parts, why)
	_, why = sshFindings(map[string]any{"complete": false, "permission": true}, nil, 5, true)
	parts = append(parts, why)

	report := strings.Join(parts, "")
	for _, want := range []string{"自動事件調查", "沒有設定 [notify] url", "沒有大於", "已停止：派遣紀錄有 1 行讀不到", "沒有結束：1 次", "沒存進派遣紀錄：1 次",
		"今天次數已滿 1", "等之後的輪次：1 個", "子 Agent 派遣", "Telegram", "事件調查 完成", "攻擊 沒有完成", "token 上限到了", "建議封鎖", "閘門",
		"這個版本不認得的欄位：1 行", "`shentu dispatch repair` 執行了 1 次", "不可信", "缺少讀取所需檔案的權限", "程式碼稽核沒檢查到", "讀不到的網頁伺服器設定",
		"應用程式相依套件的漏洞檢查沒有做完", "（另外 1 個）", "另外還有 2 個 lock 檔", "沒有比對 CISA KEV", "有 2 個漏洞沒有比對", "網域名稱查詢失敗",
		"攻擊偵測：", "這一輪要發的警報：2 則", "SSH 登入", "下限（用 root"} {
		if !strings.Contains(report, want) {
			t.Errorf("no %q in:\n%s", want, report)
		}
	}
	if left := englishLeft(report); len(left) > 0 {
		t.Errorf("English left in the Chinese report: %q\n%s", left, report)
	}
	// The same sections in English are as before (a part of them).
	if s := dispatchSection([]dispatchRecord{rec}, 1, nil, false); !strings.Contains(s, "- sub-agents: attack incomplete 1, incident complete 1\n") || !strings.Contains(s, "telegram 1; partial 1") {
		t.Errorf("English section:\n%s", s)
	}
}
