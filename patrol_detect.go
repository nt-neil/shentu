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
}

// saveSurface writes the surface the daily round built.
func saveSurface(dir string, s detect.Surface, roots []string, now time.Time) error {
	b, err := json.Marshal(surfaceCache{Version: 1, BuiltAt: now.UTC(), Surface: s, CodeRoots: roots})
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, surfaceFile), b)
}

// loadSurface is the cached surface and, when it is missing, unreadable
// or older than surfaceStale, what to say about it (Chinese).
func loadSurface(dir string, now time.Time) (detect.Surface, []string, string) {
	b, err := os.ReadFile(filepath.Join(dir, surfaceFile))
	if errors.Is(err, fs.ErrNotExist) {
		return detect.Surface{}, nil, "漏洞面資料尚未建立（每日巡檢會建立），這輪只能比對不分漏洞的類別簽章，無法判定 L1～L3"
	}
	var c surfaceCache
	if err == nil {
		err = json.Unmarshal(b, &c)
	}
	if err != nil || c.Version != 1 {
		return detect.Surface{}, nil, fmt.Sprintf("漏洞面資料無法讀取（%v），這輪無法判定 L1～L3，請檢查每日巡檢", err)
	}
	if age := now.Sub(c.BuiltAt); age > surfaceStale {
		return c.Surface, c.CodeRoots, fmt.Sprintf("漏洞面資料過期：上次更新是 %s（%.0f 小時前），這輪用的是舊資料，新裝的套件或新改的程式碼不在其中", c.BuiltAt.Local().Format(time.DateTime), age.Hours())
	}
	return c.Surface, c.CodeRoots, ""
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
// sinks and the application dependencies' vulnerabilities.
func buildSurface(audit tools.CodeAudit, apps []tools.AppResult) detect.Surface {
	return detect.Build(tools.SurfaceCode(audit.Findings), tools.SurfaceApps(apps))
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

// detectRound runs one round of attack detection: read and judge (bounded
// by detectTimeout), push what is due and the notices, save. dryRun
// prints instead of sending and saves nothing. daily also writes the
// report file.
func detectRound(ctx context.Context, cfg *Config, env *tools.Env, now time.Time, daily, dryRun bool) detectSummary {
	var sum detectSummary
	if detectOS != "linux" {
		return sum
	}
	surface, roots, stale := loadSurface(cfg.StateDir, now)
	sigs, err := detectSigs()
	if err != nil {
		sum.Err = err.Error()
		return sum
	}
	src, err := detectSource()
	if err != nil {
		sum.Err = err.Error()
		return sum
	}
	in := detect.PassInput{Src: src, Sources: detectSources, StateDir: cfg.StateDir, Surface: surface, Sigs: sigs, Now: now,
		Budget: detect.NewBudget(detect.DefaultBudgetBytes, detectRead), Loc: time.Local, CodeRoots: roots}
	p, err := runPassBounded(ctx, in)
	if err != nil {
		sum.Err = err.Error()
		return sum
	}
	defer p.Close()
	sum.Round = p.Round
	due := p.Due()
	sum.Due = len(due)
	for _, g := range due {
		text := detect.AlertText(g, &surface)
		if dryRun {
			fmt.Printf("Attack attempt\n\n%s\n", text)
			continue
		}
		if err := detectNotify(ctx, env, "Attack attempt", text, notifySeverity(g.Severity)); err != nil {
			sum.Err = "notify failed (the group stays due): " + err.Error()
			break
		}
		p.Notified(g)
		sum.Sent++
	}
	notices := p.NoticeText()
	if stale != "" {
		notices = "【Shentu 攻擊偵測】" + stale + "\n" + notices
	}
	if notices != "" {
		if dryRun {
			fmt.Printf("Attack detection notice\n\n%s\n", notices)
		} else if err := detectNotify(ctx, env, "Attack detection notice", notices, "warning"); err == nil {
			p.NoticesSent()
		}
	}
	if daily {
		sum.Levels = map[string]int{}
		for _, gs := range []map[string]*detect.Group{p.Attacks().Groups, p.Attacks().Overflow} {
			for _, g := range gs {
				if now.Sub(g.Last) <= 24*time.Hour {
					sum.Levels[g.Level]++
				}
			}
		}
		path, err := writeAttackReport(cfg.StateDir, p.Attacks(), &surface, p.Round, stale, now)
		if err != nil {
			sum.Err = strings.TrimSpace(sum.Err + "; report: " + err.Error())
		}
		sum.ReportPath = path
	}
	if dryRun {
		return sum
	}
	if err := p.Save(); err != nil {
		sum.Err = strings.TrimSpace(sum.Err + "; save: " + err.Error())
	}
	return sum
}

// runPassBounded runs a round, giving it up after detectTimeout: a read
// stuck on a dead mount cannot be interrupted. A round given up keeps the
// sources it finished, their cursors and what they gave (PassRound.
// Abandon), and says so; the one being read is read again next round.
func runPassBounded(ctx context.Context, in detect.PassInput) (*detect.PassRound, error) {
	p, err := detect.NewPass(in)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, detectTimeout)
	defer cancel()
	done := make(chan struct{})
	go func() {
		p.Run(ctx)
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		p.Abandon(detectTimeout)
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
func writeAttackReport(dir string, a *detect.Attacks, s *detect.Surface, r detect.Round, stale string, now time.Time) (string, error) {
	rd := filepath.Join(dir, reportsDir)
	if err := os.MkdirAll(rd, 0o700); err != nil {
		return "", err
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
	fmt.Fprintf(&b, "Shentu 攻擊偵測報告 %s（過去 24 小時；IP 已部分遮罩，可對外分享）\n\n", now.Local().Format(time.DateOnly))
	if stale != "" {
		b.WriteString("注意：" + stale + "\n\n")
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
	fmt.Fprintf(&b, "- alerts sent this round: %d of %d due; noise %d, unanchored %d, undetermined (cut) %d\n", s.Sent, s.Due, s.Round.Noise, s.Round.Unanchored, s.Round.Unknown)
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
	surface, roots, stale := loadSurface(cfg.StateDir, now)
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
	if stale != "" {
		notices = stale + "\n" + notices
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
