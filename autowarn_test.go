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

// v054-train: #161 and #165 each warn at start that auto_incident can
// never start a check (too small a monthly_tokens; no [notify] url). With
// both true, both are said, the budget one first, where the bot starts to
// serve and on the daily patrol.
func TestAutoWarningsBothInOrder(t *testing.T) {
	if testing.Short() || runtime.GOOS == "windows" {
		t.Skip("builds the binary")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "shentu")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cfgPath := filepath.Join(dir, "shentu.toml")
	os.WriteFile(cfgPath, []byte("state_dir = "+strconv.Quote(filepath.Join(dir, "state"))+"\n[budget]\nmonthly_tokens = 100000\n[agents]\nauto_incident = true\n"), 0o600)
	run := func(args ...string) string {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = append(os.Environ(), "SHENTU_CONFIG="+cfgPath)
		out, _ := cmd.CombinedOutput() // the command's own work may fail here (no model, no bot token)
		return string(out)
	}
	const budget = "shentu: warning: auto_incident is on, but [budget] monthly_tokens = 100000 is not more than 150000"
	const notify = "shentu: warning: auto_incident is on, but no [notify] url is set"
	for _, args := range [][]string{{"patrol", "--daily", "--dry-run"}, {"bot"}} {
		out := run(args...)
		b, n := strings.Index(out, budget), strings.Index(out, notify)
		if b < 0 || n < 0 || b > n {
			t.Errorf("%v: want the budget warning (at %d) before the notify one (at %d):\n%s", args, b, n, out)
		}
	}
}
