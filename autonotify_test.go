package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// v0.5.3 real-bot acceptance: auto_incident on without a [notify] url
// never starts a check (it starts from an L3 alert the patrol pushed, and
// the patrol pushes through the notify url alone) and says nothing. It is
// said now, in the daily report, with how to set the url.
func TestAutoNotifyMissingWarned(t *testing.T) {
	cfg := &Config{StateDir: t.TempDir()}
	cfg.Agents.AutoIncident = true
	cfg.Budget.MonthlyTokens = 1_000_000
	w := autoNotifyWarning(cfg)
	if !strings.Contains(w, "[notify] url") || !strings.Contains(w, "telegram://") || !strings.Contains(w, "sudo shentu setup") {
		t.Errorf("warning: %q", w)
	}
	if s := autoIncidentSection(cfg, time.Now()); !strings.Contains(s, "- "+w) {
		t.Errorf("daily report:\n%s", s)
	}
	cfg.Bot.TelegramToken = "1:" + "T" // a bot alone does not carry the patrol's alerts
	if autoNotifyWarning(cfg) == "" {
		t.Error("not warned with a bot token but no notify url")
	}
	cfg.Notify.URL = "https://hooks.slack.com/services/x"
	if w := autoNotifyWarning(cfg); w != "" {
		t.Errorf("warned with a notify url: %q", w)
	}
	if s := autoIncidentSection(cfg, time.Now()); strings.Contains(s, "no [notify] url") {
		t.Errorf("daily report with a notify url:\n%s", s)
	}
	cfg.Notify.URL, cfg.Agents.AutoIncident = "", false
	if w := autoNotifyWarning(cfg); w != "" {
		t.Errorf("warned with auto_incident off: %q", w)
	}
}

// The binary warns on stderr when it loads such a configuration.
func TestAutoNotifyMissingCLI(t *testing.T) {
	if testing.Short() || runtime.GOOS == "windows" {
		t.Skip("builds the binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "shentu")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	run := func(extra string) string {
		cfgPath := filepath.Join(dir, "shentu.toml")
		os.WriteFile(cfgPath, []byte("state_dir = "+strconv.Quote(filepath.Join(dir, "state"))+"\n"+extra), 0o600)
		cmd := exec.Command(bin, "usage")
		cmd.Env = append(os.Environ(), "SHENTU_CONFIG="+cfgPath)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("usage: %v\n%s", err, out)
		}
		return string(out)
	}
	if out := run("[agents]\nauto_incident = true\n"); !strings.Contains(out, "shentu: warning: auto_incident is on, but no [notify] url is set") {
		t.Errorf("no warning:\n%s", out)
	}
	if out := run("[notify]\nurl = \"https://hooks.slack.com/services/x\"\n[agents]\nauto_incident = true\n"); strings.Contains(out, "no [notify] url") {
		t.Errorf("warned with a url:\n%s", out)
	}
}
