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
	// Both commands stop right after the warnings, before any work on this
	// host, so the output holds no report of it (S-194-1): the patrol at its
	// state dir, which lies under a regular file; the bot at its missing
	// Telegram token.
	blocker := filepath.Join(dir, "not-a-dir")
	os.WriteFile(blocker, nil, 0o600)
	os.WriteFile(cfgPath, []byte("state_dir = "+strconv.Quote(filepath.Join(blocker, "state"))+"\n[budget]\nmonthly_tokens = 100000\n[agents]\nauto_incident = true\n"), 0o600)
	run := func(args ...string) string {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = append(os.Environ(), "SHENTU_CONFIG="+cfgPath)
		out, _ := cmd.CombinedOutput() // it fails where it stops, as above
		return string(out)
	}
	stopped := map[string]string{"patrol": "not-a-dir", "bot": "no Telegram bot token"}
	const budget = "shentu: warning: auto_incident is on, but [budget] monthly_tokens = 100000 is not more than 150000"
	const notify = "shentu: warning: auto_incident is on, but no [notify] url is set"
	for _, args := range [][]string{{"patrol", "--daily", "--dry-run"}, {"bot"}} {
		out := run(args...)
		b, n := strings.Index(out, budget), strings.Index(out, notify)
		// Positions and length only: on a failure the output is not printed (S-194-1).
		if b < 0 || n < 0 || b > n {
			t.Errorf("%v: want the budget warning (at %d) before the notify one (at %d); output %d bytes", args, b, n, len(out))
		}
		if !strings.Contains(out, stopped[args[0]]) {
			t.Errorf("%v: did not stop where expected (%q); output %d bytes", args, stopped[args[0]], len(out))
		}
	}
}
