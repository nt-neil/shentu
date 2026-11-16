package main

import (
	"bytes"
	"context"
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
	if _, _, note := loadSurface(dir, now); !strings.Contains(note, "尚未建立") {
		t.Errorf("missing: %q", note)
	}
	s := detect.Build([]detect.CodeSink{{Rule: "r", CWE: "CWE-89", Path: "a.php", Line: 1}}, nil)
	if err := saveSurface(dir, s, []string{"/srv/www"}, now); err != nil {
		t.Fatal(err)
	}
	got, roots, note := loadSurface(dir, now.Add(time.Hour))
	if note != "" || len(got.Entries) != 1 || roots[0] != "/srv/www" {
		t.Errorf("fresh: %q %+v %v", note, got, roots)
	}
	if _, _, note = loadSurface(dir, now.Add(surfaceStale+time.Hour)); !strings.Contains(note, "漏洞面資料過期") {
		t.Errorf("stale: %q", note)
	}
	os.WriteFile(filepath.Join(dir, surfaceFile), []byte("{"), 0o600)
	if _, _, note = loadSurface(dir, now); !strings.Contains(note, "無法讀取") {
		t.Errorf("unreadable: %q", note)
	}
}

func TestDetectRound(t *testing.T) {
	cfg, logs, out := detectSetup(t)
	now := time.Now()
	s := detect.Build([]detect.CodeSink{{Rule: "php-sqli", CWE: "CWE-89", Severity: "warning", Path: "app/x.php", Line: 12,
		Routes: []engine.RouteRef{{Model: "m", Framework: "laravel", Method: "get", Pattern: "/marker/{id}", File: "r.php", Line: 3}}}}, nil)
	if err := saveSurface(cfg.StateDir, s, nil, now); err != nil {
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
	if sec := detectSection(sum); !strings.Contains(sec, "alerts sent this round: 1 of 1") {
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
	if sum = detectRound(context.Background(), cfg, nil, now, false, false); sum != (detectSummary{}) {
		t.Errorf("not linux: %+v", sum)
	}
}

// /attacks: the last day's groups, one line each, cut to the answer level.
func TestAttacksBrief(t *testing.T) {
	cfg := &Config{StateDir: t.TempDir()}
	now := time.Now()
	if s := attacksBrief(cfg, now, true); !strings.Contains(s, "沒有攻擊嘗試") {
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
