package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/nt-neil/shentu/detect"
	"github.com/nt-neil/shentu/detect/sig"
	"github.com/nt-neil/shentu/hostenv"
	"github.com/nt-neil/shentu/rules/engine"
	"github.com/nt-neil/shentu/tools"
)

// P5 part 2: attack detection in the patrol. Neutral markers only.

const markerSig = `
[[signature]]
id = "class-marker"
title = "a class signature"
class = "sqli"
source = "shentu"
license = "Apache-2.0"
[[signature.match]]
part = "any_param"
contains = ["marker-one"]
`

const combinedSpec = `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`

type detectFake struct{ logs []hostenv.LogSource }

func (f detectFake) WebLogs(hostenv.Source) hostenv.Obs[[]hostenv.LogSource] {
	return hostenv.OK(f.logs)
}
func (f detectFake) AppUnits(hostenv.Source) hostenv.Obs[[]hostenv.AppUnit] {
	return hostenv.OK[[]hostenv.AppUnit](nil)
}
func (f detectFake) WebAccounts(hostenv.Source) hostenv.WebAccounts { return hostenv.WebAccounts{} }

type sent struct{ title, text, sev string }

// detectSetup points the round at a temporary log directory, the marker
// signature, and a recorder for what it sends.
func detectSetup(t *testing.T) (*Config, string, *[]sent) {
	t.Helper()
	logs := t.TempDir()
	cfg := &Config{StateDir: t.TempDir()}
	var out []sent
	src := &hostenv.Live{Remap: map[string]string{"/logs": logs}}
	oldSrc, oldSrcs, oldN, oldOS, oldSigs := detectSource, detectSources, detectNotify, detectOS, detectSigs
	t.Cleanup(func() {
		detectSource, detectSources, detectNotify, detectOS, detectSigs = oldSrc, oldSrcs, oldN, oldOS, oldSigs
	})
	detectSource = func() (hostenv.Source, error) { return src, nil }
	detectSources = detectFake{logs: []hostenv.LogSource{{Path: "/logs/access.log", Server: "nginx", Kind: "access", Format: "combined", Spec: combinedSpec}}}
	detectNotify = func(_ context.Context, _ *tools.Env, title, text, sev string) error {
		out = append(out, sent{title, text, sev})
		return nil
	}
	detectOS = "linux"
	detectSigs = func() ([]sig.Signature, error) {
		return sig.LoadFS(fstest.MapFS{"s/a.toml": {Data: []byte(markerSig)}}, "s")
	}
	return cfg, logs, &out
}

func logLine(ip string, at time.Time, target string) string {
	return fmt.Sprintf("%s - - [%s] \"GET %s HTTP/1.1\" 200 512 \"-\" \"marker-agent\"\n", ip, at.Format("02/Jan/2006:15:04:05 -0700"), target)
}

func TestLoadSurface(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 16, 9, 0, 0, 0, time.UTC)
	if _, _, notes := loadSurface(dir, now); !strings.Contains(strings.Join(notes, ""), "尚未建立") {
		t.Errorf("missing: %q", notes)
	}
	s := detect.Build([]detect.CodeSink{{Rule: "r", CWE: "CWE-89", Path: "a.php", Line: 1}}, nil)
	if err := saveSurface(dir, s, []string{"/srv/www"}, nil, now); err != nil {
		t.Fatal(err)
	}
	got, roots, notes := loadSurface(dir, now.Add(time.Hour))
	if len(notes) != 0 || len(got.Entries) != 1 || roots[0] != "/srv/www" {
		t.Errorf("fresh: %q %+v %v", notes, got, roots)
	}
	if _, _, notes = loadSurface(dir, now.Add(surfaceStale+time.Hour)); !strings.Contains(strings.Join(notes, ""), "漏洞面資料過期") {
		t.Errorf("stale: %q", notes)
	}
	// Review 1 of #91 (S-12): dated in the future is stale too.
	if _, _, notes = loadSurface(dir, now.Add(-time.Hour)); !strings.Contains(strings.Join(notes, ""), "在未來") {
		t.Errorf("future: %q", notes)
	}
	os.WriteFile(filepath.Join(dir, surfaceFile), []byte("{"), 0o600)
	if _, _, notes = loadSurface(dir, now); !strings.Contains(strings.Join(notes, ""), "無法讀取") {
		t.Errorf("unreadable: %q", notes)
	}
}

func TestDetectRound(t *testing.T) {
	cfg, logs, out := detectSetup(t)
	now := time.Now()
	s := detect.Build([]detect.CodeSink{{Rule: "php-sqli", CWE: "CWE-89", Severity: "warning", Path: "app/x.php", Line: 12,
		Routes: []engine.RouteRef{{Model: "m", Framework: "laravel", Method: "get", Pattern: "/marker/{id}", File: "r.php", Line: 3}}}}, nil)
	if err := saveSurface(cfg.StateDir, s, nil, nil, now); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(logs, "access.log"), []byte(logLine("198.51.100.7", now, "/marker/5?q=marker-one")+logLine("192.0.2.1", now, "/marker/6")), 0o640)
	sum := detectRound(context.Background(), cfg, nil, now, true, false)
	if sum.Err != "" || sum.Due != 1 || sum.Sent != 1 {
		t.Fatalf("round %+v, sent %+v", sum, *out)
	}
	if (*out)[0].title != "Attack attempt" || !strings.Contains((*out)[0].text, "198.51.100.7") || !strings.Contains((*out)[0].text, "L2") {
		t.Errorf("alert %+v", (*out)[0])
	}
	report, err := os.ReadFile(sum.ReportPath)
	if err != nil || strings.Contains(string(report), "198.51.100.7") || !strings.Contains(string(report), "198.51.x.x") || !strings.Contains(string(report), "192.0.x.x") {
		t.Errorf("report (masked, L1 too): %v\n%s", err, report)
	}
	if st, _ := os.Stat(sum.ReportPath); st.Mode().Perm() != 0o600 {
		t.Errorf("report mode %v", st.Mode())
	}
	if sec := detectSection(sum); !strings.Contains(sec, "alerts due this round: 1") || !strings.Contains(sec, "L2 1, L1 1") {
		t.Errorf("daily section %q", sec)
	}
	// The next round: nothing new, nothing sent again.
	*out = nil
	sum = detectRound(context.Background(), cfg, nil, now.Add(time.Hour), false, false)
	if sum.Due != 0 || len(*out) != 0 {
		t.Errorf("second round %+v %+v", sum, *out)
	}
}

// A failed send leaves the group due; a stale surface is said; a dry run
// sends and saves nothing.
func TestDetectRoundFailures(t *testing.T) {
	cfg, logs, out := detectSetup(t)
	now := time.Now()
	os.WriteFile(filepath.Join(logs, "access.log"), []byte(logLine("198.51.100.7", now, "/x?q=marker-one")), 0o640)
	var buf bytes.Buffer
	if err := detectCommand(context.Background(), cfg, time.Hour, false, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "尚未建立") || len(*out) != 0 {
		t.Errorf("detect command:\n%s", buf.String())
	}
	sum := detectRound(context.Background(), cfg, nil, now, false, true) // dry run
	if len(*out) != 0 || sum.Err != "" {
		t.Errorf("dry run sent %+v (%s)", *out, sum.Err)
	}
	sum = detectRound(context.Background(), cfg, nil, now, false, false)
	if len(*out) != 1 || !strings.Contains((*out)[0].text, "漏洞面資料尚未建立") {
		t.Errorf("stale surface not said: %+v", *out)
	}
	detectOS = "windows"
	if sum = detectRound(context.Background(), cfg, nil, now, false, false); sum.Due != 0 || sum.Err != "" || sum.Levels != nil {
		t.Errorf("not linux: %+v", sum)
	}
}

// /attacks: the last day's groups, one line each, cut to the answer level.
func TestAttacksBrief(t *testing.T) {
	cfg := &Config{StateDir: t.TempDir()}
	now := time.Now()
	if s := attacksBrief(cfg, now, true); !strings.Contains(s, "尚未建立攻擊偵測狀態") { // review 1 of #91 (S-13): not "no attacks"
		t.Errorf("empty: %q", s)
	}
	a, err := detect.LoadAttacks(cfg.StateDir, now)
	if err != nil {
		t.Fatal(err)
	}
	a.Add(detect.Attempt{IP: "198.51.100.7", Entry: "code:marker:a.php:1", Level: detect.LevelPayload, Verified: true, Time: now, Severity: "high"}, now)
	if err := a.Save(cfg.StateDir, now); err != nil {
		t.Fatal(err)
	}
	a.Close()
	s := attacksBrief(cfg, now, true)
	if !strings.Contains(s, "1 組") || !strings.Contains(s, "198.51.100.7") || !strings.Contains(s, "verified") {
		t.Errorf("brief %q", s)
	}
	cfg.Bot.Answers = 1
	if s := attacksBrief(cfg, now, false); len([]rune(s)) > maxAnswer(1)+1 {
		t.Errorf("not cut to the answer level: %d", len([]rune(s)))
	}
}

// Review 1 of #91 (N-3): a part that failed keeps the previous surface's
// entries, and the partial surface is said.
func TestSurfacePartial(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	full := detect.Build(nil, []detect.PackageVuln{{Source: "/srv/composer.lock", Ecosystem: "Packagist", Package: "marker/app", Version: "1.0", ID: "CVE-2099-0300"},
		{Source: "os", Ecosystem: "Debian:12", Package: "marker-os", Version: "1.0-1", ID: "CVE-2099-0301"}})
	if err := saveSurface(dir, full, nil, nil, now); err != nil {
		t.Fatal(err)
	}
	fresh := detect.Build(nil, []detect.PackageVuln{{Source: "os", Ecosystem: "Debian:12", Package: "marker-os", Version: "1.0-1", ID: "CVE-2099-0301"}})
	merged := keepPrevious(dir, fresh, map[string]bool{"/srv/composer.lock": true}, false) // that lock file's check failed (AppResult.Error)
	if len(merged.Entries) != 2 {
		t.Fatalf("entries %+v", merged.Entries)
	}
	if err := saveSurface(dir, merged, nil, []string{"應用程式相依套件（marker）"}, now); err != nil {
		t.Fatal(err)
	}
	if _, _, notes := loadSurface(dir, now); !strings.Contains(strings.Join(notes, ""), "漏洞面資料不完整") {
		t.Errorf("partial not said: %q", notes)
	}
}

func seedDue(t *testing.T, dir string, n int, now time.Time) {
	t.Helper()
	a, err := detect.LoadAttacks(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		a.Add(detect.Attempt{IP: fmt.Sprintf("198.51.100.%d", i+1), Entry: fmt.Sprintf("code:marker:a.php:%d", i+1), Level: detect.LevelPayload,
			Verified: true, Time: now, Severity: "high"}, now)
	}
	if err := a.Save(dir, now); err != nil {
		t.Fatal(err)
	}
	a.Close()
}

// Review 1 of #91 (N-4): at most MaxAlertsPerRound alerts one by one, the
// rest in one summary, all marked sent.
func TestDetectAlertCap(t *testing.T) {
	cfg, logs, out := detectSetup(t)
	now := time.Now()
	os.WriteFile(filepath.Join(logs, "access.log"), nil, 0o640)
	seedDue(t, cfg.StateDir, MaxAlertsPerRound+5, now)
	sum := detectRound(context.Background(), cfg, nil, now, false, false)
	alerts, summaries := 0, 0
	for _, m := range *out {
		switch {
		case m.title == "Attack attempt":
			alerts++
		case strings.HasSuffix(m.title, "more attack attempts"):
			summaries++
			if !strings.Contains(m.text, "另有 5 組") || strings.Contains(m.text, "只會針對單一 IP") {
				t.Errorf("summary:\n%s", m.text)
			}
		}
	}
	if alerts != MaxAlertsPerRound || summaries != 1 || sum.Sent != MaxAlertsPerRound+5 {
		t.Errorf("%d alerts, %d summaries, sent %d", alerts, summaries, sum.Sent)
	}
	*out = nil
	if sum = detectRound(context.Background(), cfg, nil, now.Add(time.Hour), false, false); sum.Due != 0 {
		t.Errorf("due again: %+v", sum)
	}
}

// Review 1 of #91 (S-7, S-15): a send that fails is said, and leaves the
// groups and the notices to the next round.
func TestDetectNotifyFails(t *testing.T) {
	cfg, logs, out := detectSetup(t)
	now := time.Now()
	os.WriteFile(filepath.Join(logs, "access.log"), nil, 0o640)
	seedDue(t, cfg.StateDir, 2, now)
	detectNotify = func(context.Context, *tools.Env, string, string, string) error { return errors.New("marker down") }
	sum := detectRound(context.Background(), cfg, nil, now, false, false)
	if sum.Sent != 0 || !strings.Contains(sum.Err, "notify (the group stays due): marker down") || !strings.Contains(sum.Err, "notices") {
		t.Errorf("%+v", sum)
	}
	detectNotify = func(_ context.Context, _ *tools.Env, title, text, sev string) error {
		*out = append(*out, sent{title, text, sev})
		return nil
	}
	if sum = detectRound(context.Background(), cfg, nil, now.Add(time.Minute), false, false); sum.Sent != 2 {
		t.Errorf("next round: %+v", sum)
	}
}

// Review 1 of #91 (S-14): the surface's notes go out once a day.
func TestSurfaceNoticeOnceADay(t *testing.T) {
	cfg, logs, out := detectSetup(t)
	now := time.Now()
	os.WriteFile(filepath.Join(logs, "access.log"), nil, 0o640)
	count := func() int {
		n := 0
		for _, m := range *out {
			if strings.Contains(m.text, "漏洞面資料尚未建立") {
				n++
			}
		}
		return n
	}
	detectRound(context.Background(), cfg, nil, now, false, false)
	detectRound(context.Background(), cfg, nil, now.Add(time.Hour), false, false)
	if count() != 1 {
		t.Errorf("said %d times in two hours", count())
	}
	detectRound(context.Background(), cfg, nil, now.Add(25*time.Hour), false, false)
	if count() != 2 {
		t.Errorf("not said again the next day: %d", count())
	}
}

// Review 1 of #91 (N-4): a state held by another shentu does not stall
// the patrol: the round is skipped and said.
func TestDetectLockBounded(t *testing.T) {
	cfg, _, _ := detectSetup(t)
	oldT, oldW := detect.LockTries, detect.LockWait
	t.Cleanup(func() { detect.LockTries, detect.LockWait = oldT, oldW })
	detect.LockTries, detect.LockWait = 2, 10*time.Millisecond
	held, err := detect.LoadAttacks(cfg.StateDir, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	done := make(chan detectSummary, 1)
	go func() { done <- detectRound(context.Background(), cfg, nil, time.Now(), false, false) }()
	select {
	case sum := <-done:
		if !strings.Contains(sum.Err, "held by another") {
			t.Errorf("%+v", sum)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the patrol waited on the lock")
	}
}

// Review 2 of #91 (N-A2): what fails after the patrol's report (the
// path patrol defers) is kept and said at the start of the next report.
func TestFinishDetectCarriesOver(t *testing.T) {
	cfg, logs, _ := detectSetup(t)
	now := time.Now()
	os.WriteFile(filepath.Join(logs, "access.log"), nil, 0o640)
	seedDue(t, cfg.StateDir, 1, now)
	detectNotify = func(context.Context, *tools.Env, string, string, string) error { return errors.New("marker 429") }
	dr := detectJudge(context.Background(), cfg, now, false, false)
	finishDetect(context.Background(), nil, dr)
	got := detectCarryOver(cfg.StateDir)
	if !strings.Contains(got, "marker 429") || !strings.Contains(got, "last patrol") {
		t.Errorf("carry-over %q", got)
	}
	if detectCarryOver(cfg.StateDir) != "" {
		t.Error("said twice")
	}
}
