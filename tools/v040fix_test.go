package tools

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// VM acceptance of adff9e6, N1: journald shows a user outside
// systemd-journal and adm only what it may see, with no error: the SSH
// counts are then not complete (a lower bound), and root would read them.
func TestJournalNotCompleteForUser(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows reads its own logon events")
	}
	oldS, oldJ := scanAuthLogs, journalAll
	t.Cleanup(func() { scanAuthLogs, journalAll = oldS, oldJ })
	scanAuthLogs = func(_ context.Context, _ hostenv.Source, _ []string, _ time.Time, add func() func(string)) (string, bool, error) {
		add()
		return "journald", true, nil
	}
	for _, c := range []struct {
		all, complete, permission bool
	}{{true, true, false}, {false, false, true}} {
		journalAll = func() bool { return c.all }
		r, err := SSHSummary(context.Background(), &Env{}, time.Now().Add(-time.Hour), "")
		if err != nil {
			t.Fatal(err)
		}
		if complete, _ := r["complete"].(bool); complete != c.complete || r["verified"] != true {
			t.Errorf("all %v: %+v", c.all, r)
		}
		if src, _ := r["source"].(string); c.all != (src == "journald") {
			t.Errorf("all %v: source %q", c.all, src)
		}
		if p, _ := r["permission"].(bool); p != c.permission {
			t.Errorf("all %v: permission %+v", c.all, r)
		}
	}
	// Text logs are judged as before.
	scanAuthLogs = func(_ context.Context, _ hostenv.Source, _ []string, _ time.Time, add func() func(string)) (string, bool, error) {
		add()
		return "/var/log/auth.log", false, nil
	}
	if r, _ := SSHSummary(context.Background(), &Env{}, time.Now().Add(-time.Hour), ""); r["complete"] != true {
		t.Errorf("text log: %+v", r)
	}
}
