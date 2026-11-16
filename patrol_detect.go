package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/nt-neil/shentu/detect"
	"github.com/nt-neil/shentu/detect/sig"
	"github.com/nt-neil/shentu/hostenv"
	"github.com/nt-neil/shentu/tools"
)

// Attack detection in the patrol (plan 0743f0, P5): each round reads the
// web logs and application units since the last, judges every request
// against the vulnerability surface the daily round built, and pushes the
// groups due (L2, L3, an Unknown threshold; never L1) as plain text, not
// through the model: the alert is the detector's own words. The daily
// round rebuilds the surface and writes the report file.

const (
	surfaceFile = "surface.json"
	// surfaceStale: a surface older than this (the daily round failed or
	// did not run) is used, and said, never quietly.
	surfaceStale = 26 * time.Hour
	reportsDir   = "reports"
	reportKeep   = 30 * 24 * time.Hour
	// detectTimeout bounds a round's reading and judging: a log on a stuck
	// mount must not hold the patrol.
	detectTimeout = 120 * time.Second
	detectRead    = 90 * time.Second
)

// surfaceCache is surface.json.
type surfaceCache struct {
	Version   int            `json:"version"`
	BuiltAt   time.Time      `json:"built_at"`
	Surface   detect.Surface `json:"surface"`
	CodeRoots []string       `json:"code_roots,omitempty"`
	// Partial: the parts that could not be built this time (their entries
	// are the previous surface's, when there was one), said every day.
	Partial []string `json:"partial,omitempty"`
}

// maxSurfaceFile bounds what is read of surface.json.
const maxSurfaceFile = 64 << 20

// saveSurface writes the surface the daily round built, and what of it is
// partial.
func saveSurface(dir string, s detect.Surface, roots, partial []string, now time.Time) error {
	b, err := json.Marshal(surfaceCache{Version: 1, BuiltAt: now.UTC(), Surface: s, CodeRoots: roots, Partial: partial})
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, surfaceFile), b)
}

// readSurface reads surface.json as the state files are read (no link
// followed, ours, bounded).
func readSurface(dir string) (surfaceCache, error) {
	var c surfaceCache
	b, err := detect.ReadStateFile(dir, surfaceFile, maxSurfaceFile)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.Version != 1 {
		return c, fmt.Errorf("version %d, not 1", c.Version)
	}
	return c, nil
}

// keepPrevious adds to s, built with some parts missing (failedApps:
// the lock files whose check failed, "*" all of them; osFailed: the OS
// packages), the previous surface's entries of those parts: one failed
// query must not leave a day of attacks on them judged noise.
func keepPrevious(dir string, s detect.Surface, failedApps map[string]bool, osFailed bool) detect.Surface {
	if len(failedApps) == 0 && !osFailed {
		return s
	}
	prev, err := readSurface(dir)
	if err != nil {
		return s
	}
	have := map[string]bool{}
	for _, e := range s.Entries {
		have[e.ID] = true
	}
	for _, e := range prev.Surface.Entries {
		if e.Kind != "package" || e.Installed || have[e.ID] {
			continue
		}
		if e.Source == "os" && osFailed || e.Source != "os" && (failedApps["*"] || failedApps[e.Source]) {
			if len(s.Entries) >= detect.MaxEntries {
				s.TruncatedPackages++
				continue
			}
			s.Entries = append(s.Entries, e)
		}
	}
	return s
}

// loadSurface is the cached surface and what to say about it (Chinese):
// missing, unreadable, older than surfaceStale (or dated in the future),
// partial, or cut at MaxEntries.
func loadSurface(dir string, now time.Time) (detect.Surface, []string, []string) {
	c, err := readSurface(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return detect.Surface{}, nil, []string{"漏洞面資料尚未建立：請執行 shentu patrol --daily 建立（加上 --dry-run 時不會建立），這輪只能比對不分漏洞的類別簽章，無法判定 L1～L3"}
	}
	if err != nil {
		return detect.Surface{}, nil, []string{"漏洞面資料無法讀取（" + detect.Printable(err.Error()) + "），這輪無法判定 L1～L3，請檢查每日巡檢"}
	}
	var notes []string
	switch age := now.Sub(c.BuiltAt); {
	case age < -5*time.Minute:
		notes = append(notes, fmt.Sprintf("漏洞面資料的建立時間在未來（%s），主機時間可能被調動過，視為過期", c.BuiltAt.Local().Format(time.DateTime)))
	case age > surfaceStale:
		notes = append(notes, fmt.Sprintf("漏洞面資料過期：上次更新是 %s（%.0f 小時前），這輪用的是舊資料，新裝的套件或新改的程式碼不在其中", c.BuiltAt.Local().Format(time.DateTime), age.Hours()))
	}
	if len(c.Partial) > 0 {
		notes = append(notes, "漏洞面資料不完整："+detect.Printable(strings.Join(c.Partial, "；"))+"（缺的部分沿用前一份，沒有前一份就缺）")
	}
	if c.Surface.TruncatedCode+c.Surface.TruncatedPackages > 0 {
		notes = append(notes, fmt.Sprintf("漏洞面超過上限 %d 條，略過程式碼 %d 條、套件 %d 條（嚴重度較低的先略過），打到它們的攻擊會被當成雜訊", detect.MaxEntries, c.Surface.TruncatedCode, c.Surface.TruncatedPackages))
	}
	return c.Surface, c.CodeRoots, notes
}

// writeAtomic writes p through a temporary file renamed over it (0600).
func writeAtomic(p string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(p), filepath.Base(p)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(b)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// buildSurface is the daily round's surface: the code audit's injection
// sinks, the application dependencies' and the OS packages'
// vulnerabilities, and the WordPress plugins installed (matched by
// signatures written for their versions).
func buildSurface(audit tools.CodeAudit, apps []tools.AppResult, osVulns []detect.PackageVuln, plugins []tools.WPPlugin) detect.Surface {
	return detect.Build(tools.SurfaceCode(audit.Findings), append(tools.SurfaceApps(apps), osVulns...), tools.SurfacePlugins(plugins)...)
}

// Seams for tests.
var (
	detectSource                 = func() (hostenv.Source, error) { return hostenv.NewLive(hostenv.ForOS("linux").Allowlist()) }
	detectSources detect.Sources = hostenv.LinuxCollector{}
	detectNotify                 = tools.Notify
	detectOS                     = runtime.GOOS
	detectSigs                   = sig.Load
)

// detectSummary is what a round gives the daily report.
type detectSummary struct {
	Sent, Due int
	// Levels: the groups seen in the last day by level (L1 included: never
	// pushed, but in the daily report and the report file).
	Levels     map[string]int
	Round      detect.Round
	ReportPath string
	Err        string
}

// MaxAlertsPerRound bounds the alerts a round pushes one by one; the rest
// go in one summary (commander, review 1 of #91: a flood of groups must
// not delay the patrol's own report or run into Telegram's limits).
const MaxAlertsPerRound = 20

// surfaceNoticeFile keeps when the surface's notes were last sent: once a
// day is enough (they hold until the next daily round).
const surfaceNoticeFile = "surface-notice.json"

// detectRun is a round read and judged, waiting to send: the patrol sends
// its own report first, then this (send).
type detectRun struct {
	cfg     *Config
	p       *detect.PassRound
	surface detect.Surface
	notes   []string
	now     time.Time
	daily   bool
	dryRun  bool
	sum     detectSummary
}

// detectJudge reads and judges a round (bounded by detectTimeout; the
// state's lock by detect.LockTries). Its sum says what failed.
func detectJudge(ctx context.Context, cfg *Config, now time.Time, daily, dryRun bool) *detectRun {
	r := &detectRun{cfg: cfg, now: now, daily: daily, dryRun: dryRun}
	if detectOS != "linux" {
		return r
	}
	surface, roots, notes := loadSurface(cfg.StateDir, now)
	r.surface, r.notes = surface, notes
	sigs, err := detectSigs()
	if err != nil {
		r.sum.Err = err.Error()
		return r
	}
	src, err := detectSource()
	if err != nil {
		r.sum.Err = err.Error()
		return r
	}
	in := detect.PassInput{Src: src, Sources: detectSources, StateDir: cfg.StateDir, Surface: surface, Sigs: sigs, Now: now,
		Budget: detect.NewBudget(detect.DefaultBudgetBytes, detectRead), Loc: time.Local, CodeRoots: roots}
	p, err := runPassBounded(ctx, in)
	if err != nil {
		r.sum.Err = err.Error()
		return r
	}
	r.p = p
	r.sum.Round = p.Round
	r.sum.Due = len(p.Due())
	if daily {
		r.sum.Levels = map[string]int{}
		for _, gs := range []map[string]*detect.Group{p.Attacks().Groups, p.Attacks().Overflow} {
			for _, g := range gs {
				if now.Sub(g.Last) <= 24*time.Hour {
					r.sum.Levels[g.Level]++
				}
			}
		}
		// The report is written now (it is about what was seen, not what
		// was sent): ReportPath only once it is.
		path, err := writeAttackReport(cfg.StateDir, p.Attacks(), &surface, p.Round, notes, now)
		if err != nil {
			r.sum.Err = strings.TrimPrefix(r.sum.Err+"; report: "+err.Error(), "; ")
		} else {
			r.sum.ReportPath = path
		}
	}
	return r
}

// detectLastFile keeps what the last patrol's attack detection could not
// do after its report went (sends, save): the next report says it.
const detectLastFile = "detect-last.json"

// finishDetect is what the patrol defers after its report: send, and
// keep what failed for the next report, and say it on stderr.
func finishDetect(ctx context.Context, env *tools.Env, dr *detectRun) {
	sum := dr.send(ctx, env)
	if sum.Err == "" || dr.dryRun {
		return
	}
	fmt.Fprintln(os.Stderr, "shentu: attack detection:", sum.Err)
	line := dr.now.UTC().Format(time.RFC3339) + ": " + sum.Err
	if old := carryOverLines(dr.cfg.StateDir); old != "" { // not said yet (its report did not go): kept
		line = old + "\n" + line
	}
	if len(line) > 8<<10 {
		line = "…" + line[len(line)-8<<10:]
	}
	b, _ := json.Marshal(map[string]string{"error": line})
	writeAtomic(filepath.Join(dr.cfg.StateDir, detectLastFile), b)
}

// carryOverLines is what the last patrols' attack detection could not do
// (finishDetect), one line each, "" for none.
func carryOverLines(dir string) string {
	b, err := detect.ReadStateFile(dir, detectLastFile, 64<<10)
	if err != nil {
		return ""
	}
	var v struct{ Error string }
	if json.Unmarshal(b, &v) != nil {
		return ""
	}
	return v.Error
}

// detectCarryOver is carryOverLines for this report's start. It stays
// until clearCarryOver, once a report saying it went out.
func detectCarryOver(dir string) string {
	if l := carryOverLines(dir); l != "" {
		return "\nAttack detection, last patrol(s) — not done after the report:\n" + l + "\n"
	}
	return ""
}

// clearCarryOver forgets what detectCarryOver said, its report sent.
func clearCarryOver(dir string) { os.Remove(filepath.Join(dir, detectLastFile)) }

// sayCarryOver sends carry, what the last patrol could not do, on its own
// when this patrol has no report to send it in; forgotten once sent.
// dryRun prints it and keeps it.
func sayCarryOver(ctx context.Context, env *tools.Env, dir, carry string, dryRun bool) error {
	if carry == "" {
		return nil
	}
	if dryRun {
		fmt.Print(carry)
		return nil
	}
	if err := detectNotify(ctx, env, "Attack detection: last patrol's sends failed", mask(strings.TrimSpace(carry)), "warning"); err != nil {
		return err
	}
	clearCarryOver(dir)
	return nil
}

// send pushes the round's alerts (MaxAlertsPerRound one by one, the rest
// in one summary), its notices, writes the daily report, saves and
// releases the state. dryRun prints and saves nothing. Safe to call once
// whatever detectJudge gave.
func (r *detectRun) send(ctx context.Context, env *tools.Env) detectSummary {
	if r.p == nil {
		return r.sum
	}
	p := r.p
	defer p.Close()
	fail := func(what string, err error) {
		r.sum.Err = strings.TrimPrefix(r.sum.Err+"; "+what+": "+err.Error(), "; ")
	}
	due := p.Due()
	for i, g := range due {
		if i == MaxAlertsPerRound {
			rest := due[i:]
			text := alertsSummary(rest)
			if r.dryRun {
				fmt.Printf("Attack attempts (summary)\n\n%s\n", text)
				break
			}
			if err := detectNotify(ctx, env, fmt.Sprintf("%d more attack attempts", len(rest)), text, notifySeverity(rest[0].Severity)); err != nil {
				fail("notify (summary; the groups stay due)", err)
				break
			}
			for _, g := range rest {
				p.Notified(g)
				r.sum.Sent++
			}
			break
		}
		text := detect.AlertText(g, &r.surface)
		if r.dryRun {
			fmt.Printf("Attack attempt\n\n%s\n", text)
			continue
		}
		if err := detectNotify(ctx, env, "Attack attempt", text, notifySeverity(g.Severity)); err != nil {
			fail("notify (the group stays due)", err)
			break
		}
		p.Notified(g)
		r.sum.Sent++
	}
	notices := p.NoticeText()
	surfaceNotes := len(r.notes) > 0 && r.surfaceNoticeDue()
	if surfaceNotes {
		for _, n := range r.notes {
			notices = "【Shentu 攻擊偵測】" + n + "\n" + notices
		}
	}
	if notices != "" {
		if r.dryRun {
			fmt.Printf("Attack detection notice\n\n%s\n", notices)
		} else if err := detectNotify(ctx, env, "Attack detection notice", notices, "warning"); err != nil {
			fail("notify (notices; sent again next round)", err)
		} else {
			p.NoticesSent()
			if surfaceNotes {
				writeAtomic(filepath.Join(r.cfg.StateDir, surfaceNoticeFile), []byte(`{"sent":"`+r.now.UTC().Format(time.RFC3339)+`"}`))
			}
		}
	}
	if r.dryRun {
		return r.sum
	}
	if err := p.Save(); err != nil {
		fail("save", err)
	}
	return r.sum
}

// surfaceNoticeDue: the surface's notes were not sent in the last day.
func (r *detectRun) surfaceNoticeDue() bool {
	b, err := detect.ReadStateFile(r.cfg.StateDir, surfaceNoticeFile, 4096)
	if err != nil {
		return true
	}
	var v struct {
		Sent time.Time `json:"sent"`
	}
	if json.Unmarshal(b, &v) != nil || v.Sent.After(r.now) {
		return true
	}
	return r.now.Sub(v.Sent) >= 24*time.Hour
}

// alertsSummary lists groups past MaxAlertsPerRound, one line each.
func alertsSummary(gs []*detect.Group) string {
	var b strings.Builder
	fmt.Fprintf(&b, "【Shentu 攻擊偵測】這輪另有 %d 組攻擊紀錄（超過單輪推播上限 %d 組，合併在這則）：\n", len(gs), MaxAlertsPerRound)
	for i, g := range gs {
		if i == 50 {
			fmt.Fprintf(&b, "…另有 %d 組，請在伺服器上用 shentu detect 查看\n", len(gs)-50)
			break
		}
		var ips []string
		for j, ip := range g.IPs {
			if j == 3 {
				break
			}
			ips = append(ips, detect.Printable(ip))
		}
		fmt.Fprintf(&b, "- [%s %s] %s ×%d %s\n", g.Severity, g.Level, detect.Printable(g.Entry), g.Count, strings.Join(ips, "、"))
	}
	b.WriteString("封鎖請個別確認：彙總不提供封鎖。\n")
	return b.String()
}

// detectRound judges and sends at once (shentu detect's tests, and a
// caller with no report of its own to send first).
func detectRound(ctx context.Context, cfg *Config, env *tools.Env, now time.Time, daily, dryRun bool) detectSummary {
	return detectJudge(ctx, cfg, now, daily, dryRun).send(ctx, env)
}

// runPassBounded runs a round, giving it up after detectTimeout: a read
// stuck on a dead mount cannot be interrupted. A round given up keeps the
// sources it finished, their cursors and what they gave (PassRound.
// Abandon), and says so; the one being read is read again next round. A
// round stopped because the patrol was (SIGTERM) is interrupted, not
// timed out.
func runPassBounded(ctx context.Context, in detect.PassInput) (*detect.PassRound, error) {
	p, err := detect.NewPass(in)
	if err != nil {
		return nil, err
	}
	run, cancel := context.WithTimeout(ctx, detectTimeout)
	defer cancel()
	done := make(chan struct{})
	go func() {
		p.Run(run)
		close(done)
	}()
	select {
	case <-done:
	case <-run.Done():
		if ctx.Err() != nil {
			p.Interrupt()
		} else {
			p.Abandon(detectTimeout)
		}
	}
	return p, nil
}

func notifySeverity(s string) string {
	switch s {
	case "critical":
		return "critical"
	case "high", "medium":
		return "warning"
	}
	return "info"
}

// writeAttackReport writes the day's report file under state_dir/reports
// (0600): every group seen in the last day, addresses masked (ReportText),
// and the round's counts; reports older than reportKeep are removed.
func writeAttackReport(dir string, a *detect.Attacks, s *detect.Surface, r detect.Round, notes []string, now time.Time) (string, error) {
	rd := filepath.Join(dir, reportsDir)
	if err := os.MkdirAll(rd, 0o700); err != nil {
		return "", err
	}
	// Ours alone: not a link someone left there, not readable by others.
	st, err := os.Lstat(rd)
	if err != nil {
		return "", err
	}
	if st.Mode()&os.ModeSymlink != 0 || !st.IsDir() || !ownDir(st) {
		return "", fmt.Errorf("%s is not a directory of its own (a link, or another user's): the report is not written", rd)
	}
	if st.Mode().Perm()&0o077 != 0 {
		if err := os.Chmod(rd, 0o700); err != nil {
			return "", err
		}
	}
	var groups []*detect.Group
	for _, gs := range []map[string]*detect.Group{a.Groups, a.Overflow} {
		for _, g := range gs {
			if now.Sub(g.Last) <= 24*time.Hour {
				groups = append(groups, g)
			}
		}
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Severity != groups[j].Severity {
			return severityRankOf(groups[i].Severity) > severityRankOf(groups[j].Severity)
		}
		return groups[i].Key < groups[j].Key
	})
	var b strings.Builder
	fmt.Fprintf(&b, "Shentu 攻擊偵測報告 %s（過去 24 小時；IP 已部分遮罩，但內含本機漏洞的位置，對外分享前請自行確認）\n\n", now.Local().Format(time.DateOnly))
	for _, n := range notes {
		b.WriteString("注意：" + n + "\n")
	}
	if len(notes) > 0 {
		b.WriteString("\n")
	}
	fmt.Fprintf(&b, "這輪統計：雜訊 %d、無對應路由的類別命中 %d、無法判定（請求被截斷）%d\n共 %d 組\n\n", r.Noise, r.Unanchored, r.Unknown, len(groups))
	for _, g := range groups {
		b.WriteString(detect.ReportText(g, s))
		b.WriteString("\n")
	}
	p := filepath.Join(rd, "attacks-"+now.Local().Format(time.DateOnly)+".txt")
	if err := writeAtomic(p, []byte(b.String())); err != nil {
		return "", err
	}
	old, _ := filepath.Glob(filepath.Join(rd, "attacks-*.txt"))
	for _, f := range old {
		if st, err := os.Stat(f); err == nil && now.Sub(st.ModTime()) > reportKeep {
			os.Remove(f)
		}
	}
	return p, nil
}

func severityRankOf(s string) int {
	return map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[s]
}

// detectSection is the daily report's lines about attack detection.
func detectSection(s detectSummary) string {
	if s.Err == "" && s.Due == 0 && s.ReportPath == "" && s.Round == (detect.Round{}) && len(s.Levels) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\nAttack detection:\n")
	if len(s.Levels) > 0 {
		fmt.Fprintf(&b, "- groups seen in the last day: L3 %d, L2 %d, L1 %d (reached a vulnerable route only: counted, not pushed), undetermined %d\n",
			s.Levels[detect.LevelSuccess], s.Levels[detect.LevelPayload], s.Levels[detect.LevelRoute], s.Levels[detect.LevelUnknown])
	}
	fmt.Fprintf(&b, "- alerts due this round: %d (pushed on their own after this report, at most %d one by one, the rest in one summary); noise %d, unanchored %d, undetermined (cut) %d\n", s.Due, MaxAlertsPerRound, s.Round.Noise, s.Round.Unanchored, s.Round.Unknown)
	if s.ReportPath != "" {
		fmt.Fprintf(&b, "- report (addresses masked): %s\n", s.ReportPath)
	}
	if s.Err != "" {
		fmt.Fprintf(&b, "- not checked: %s\n", s.Err)
	}
	return b.String()
}

// detectCommand is `shentu detect`: a round read and judged, for an
// operator or an acceptance test. It sends nothing and saves nothing (the
// logs are read again by the next patrol): it lists the groups seen within
// since (addresses in full: this is the server's own terminal) and the
// round's notices.
func detectCommand(ctx context.Context, cfg *Config, since time.Duration, asJSON bool, out io.Writer) error {
	if detectOS != "linux" {
		return errors.New("attack detection reads Linux web logs; this host is " + detectOS)
	}
	now := time.Now()
	surface, roots, notes := loadSurface(cfg.StateDir, now)
	sigs, err := detectSigs()
	if err != nil {
		return err
	}
	src, err := detectSource()
	if err != nil {
		return err
	}
	p, err := runPassBounded(ctx, detect.PassInput{Src: src, Sources: detectSources, StateDir: cfg.StateDir, Surface: surface, Sigs: sigs, Now: now,
		Budget: detect.NewBudget(detect.DefaultBudgetBytes, detectRead), Loc: time.Local, CodeRoots: roots})
	if err != nil {
		return err
	}
	defer p.Close()
	var groups []*detect.Group
	for _, gs := range []map[string]*detect.Group{p.Attacks().Groups, p.Attacks().Overflow} {
		for _, g := range gs {
			if now.Sub(g.Last) <= since {
				groups = append(groups, g)
			}
		}
	}
	sort.Slice(groups, func(i, j int) bool {
		if a, b := severityRankOf(groups[i].Severity), severityRankOf(groups[j].Severity); a != b {
			return a > b
		}
		return groups[i].Key < groups[j].Key
	})
	notices := p.NoticeText()
	for _, n := range notes {
		notices = n + "\n" + notices
	}
	if asJSON {
		b, err := json.MarshalIndent(map[string]any{"groups": groups, "round": p.Round, "sources": p.Sources, "notices": notices}, "", "  ")
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(b))
		return err
	}
	for _, g := range groups {
		fmt.Fprintln(out, detect.AlertText(g, &surface))
	}
	fmt.Fprintf(out, "%d group(s) seen within %s; noise %d, unanchored %d, undetermined %d\n", len(groups), since, p.Round.Noise, p.Round.Unanchored, p.Round.Unknown)
	if notices != "" {
		fmt.Fprintln(out, notices)
	}
	return nil
}

// attacksBrief is the bot's /attacks: the groups of the last day, one line
// each, cut to the bot's answer length (Answers). Addresses in full, as the
// alerts give them.
func attacksBrief(cfg *Config, now time.Time, zh bool) string {
	if !detect.AttacksExist(cfg.StateDir) { // not run yet: not "no attacks"
		if zh {
			return "🛡 尚未建立攻擊偵測狀態：巡檢還沒跑過攻擊偵測，不代表沒有攻擊。"
		}
		return "🛡 Attack detection has no state yet: the patrol has not run it, which does not mean no attacks."
	}
	st, err := detect.PeekAttacks(cfg.StateDir)
	if err != nil {
		return "⚠️ " + err.Error()
	}
	list, _ := tools.AttackList(st, now, 24*time.Hour)["groups"].([]map[string]any)
	if len(list) == 0 {
		if zh {
			return "🛡 過去 24 小時沒有攻擊嘗試的紀錄。"
		}
		return "🛡 No attack attempts in the last 24 hours."
	}
	var b strings.Builder
	if zh {
		fmt.Fprintf(&b, "🛡 過去 24 小時的攻擊嘗試（%d 組）：\n", len(list))
	} else {
		fmt.Fprintf(&b, "🛡 Attack attempts, last 24 hours (%d groups):\n", len(list))
	}
	for _, g := range list {
		v := "verified"
		if g["verified"] == false {
			v = "unverified"
		}
		fmt.Fprintf(&b, "- [%s %s] %s ×%d %v (%s)\n", g["severity"], g["level"], g["entry"], g["count"], g["ips"], v)
	}
	s := b.String()
	if n := maxAnswer(cfg.Bot.Answers); n > 0 {
		s = tools.Cut(s, n)
	}
	return s
}

// saveDailySurface builds and saves the vulnerability surface from the
// daily patrol's checks (plugins read here), before its report is sent;
// what it could not do is returned for the report.
func saveDailySurface(cfg *Config, env *tools.Env, audit tools.CodeAudit, web []string, apps []tools.AppResult, osSurface []detect.PackageVuln,
	failedApps map[string]bool, osFailed bool, partial []string, now time.Time) (unchecked string) {
	plugins, unreadPlugins := tools.WordPressPlugins(web)
	if len(unreadPlugins) > 0 { // paths the web account may name: quoted, masked, a few
		unchecked += "\nAttack detection: WordPress plugin directories not read:\n"
		for i, u := range unreadPlugins {
			if i == 10 {
				unchecked += fmt.Sprintf("- (%d more)\n", len(unreadPlugins)-10)
				break
			}
			unchecked += fmt.Sprintf("- %q\n", mask(u))
		}
	}
	if audit.Unfinished || len(audit.NotChecked) > 0 {
		partial = append(partial, "程式碼稽核沒有全部完成（見日報的 not checked）")
	}
	if len(unreadPlugins) > 0 {
		partial = append(partial, fmt.Sprintf("WordPress 外掛有 %d 處讀不到（見日報）", len(unreadPlugins)))
	}
	surface := keepPrevious(cfg.StateDir, buildSurface(audit, apps, osSurface, plugins), failedApps, osFailed)
	if err := saveSurface(cfg.StateDir, surface, env.AppPaths, partial, now); err != nil {
		unchecked += "\nAttack detection: the vulnerability surface could not be saved: " + err.Error() + "\n"
	}
	return unchecked
}
