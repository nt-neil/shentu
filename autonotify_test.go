package main

import (
	"context"
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

// The binary warns on stderr on the daily patrol (and when the bot starts
// to serve), not on every command.
func TestAutoNotifyMissingCLI(t *testing.T) {
	if testing.Short() || runtime.GOOS == "windows" {
		t.Skip("builds the binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "shentu")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	// The warning is said before the patrol's work, which may fail here
	// (no model): its exit is not what is checked.
	run := func(extra string, args ...string) string {
		cfgPath := filepath.Join(dir, "shentu.toml")
		os.WriteFile(cfgPath, []byte("state_dir = "+strconv.Quote(filepath.Join(dir, "state"))+"\n"+extra), 0o600)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = append(os.Environ(), "SHENTU_CONFIG="+cfgPath)
		out, _ := cmd.CombinedOutput()
		return string(out)
	}
	const on = "[agents]\nauto_incident = true\n"
	const warned = "shentu: warning: auto_incident is on, but no [notify] url is set"
	if out := run(on, "patrol", "--daily", "--dry-run"); !strings.Contains(out, warned) {
		t.Errorf("no warning on the daily patrol:\n%s", out)
	}
	if out := run(on, "usage"); strings.Contains(out, warned) {
		t.Errorf("warned on another command:\n%s", out)
	}
	if out := run("[notify]\nurl = \"https://hooks.slack.com/services/x\"\n"+on, "patrol", "--daily", "--dry-run"); strings.Contains(out, "no [notify] url") {
		t.Errorf("warned with a url:\n%s", out)
	}
}
