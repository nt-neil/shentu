package hostenv

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// journalToo is a live tree whose journald repeats the log's lines.
type journalToo struct {
	*Live
	lines  []string
	called bool
}

func (j *journalToo) RunLinesUnmasked(_ context.Context, _ []string, fn func(string)) (CmdResult, error) {
	j.called = true
	for _, l := range j.lines {
		fn(l)
	}
	return CmdResult{}, nil
}

// An auth log cut short (journald empty) counts once and says so.
func TestAuthLogCutShortCountsOnce(t *testing.T) {
	now := time.Now()
	line := now.Add(-time.Hour).UTC().Format(time.RFC3339) + " vm sshd[1]: Failed password for root from 203.0.113.7 port 22 ssh2"
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "auth.log"), []byte(line+"\n"+strings.Repeat("x", MaxLineBytes+1)+"\n"+line+"\n"), 0o600)
	src := &journalToo{Live: &Live{Remap: map[string]string{"/var/log": dir}}}
	f := LinuxCollector{}.AuthEvents(context.Background(), src, now, []string{"/var/log/auth.log"})
	if !src.called || f.Status != StatusPartial || f.Reason != ReasonTruncated || f.Value.FailedBySrc["203.0.113.7"] != 1 || !strings.Contains(f.Detail, "unverified") {
		t.Errorf("journald read %v, %s %s %q %v", src.called, f.Status, f.Reason, f.Detail, f.Value.FailedBySrc)
	}
	_, _, err := LinuxCollector{}.ScanAuthLogs(context.Background(), src, []string{"/var/log/auth.log"}, now.Add(-24*time.Hour), func() func(string) { return func(string) {} })
	if !errors.Is(err, ErrTruncated) {
		t.Errorf("err %v", err)
	}
}

// journaldAt answers journalctl only at one path.
type journaldAt struct {
	*Live
	path string
	ran  []string
}

func (j *journaldAt) RunLinesUnmasked(_ context.Context, argv []string, fn func(string)) (CmdResult, error) {
	j.ran = append(j.ran, argv[0])
	if argv[0] != j.path {
		return CmdResult{}, &os.PathError{Op: "exec", Path: argv[0], Err: os.ErrNotExist}
	}
	fn(time.Now().UTC().Format(time.RFC3339) + " vm sshd[1]: Failed password for root from 203.0.113.8 port 22 ssh2")
	return CmdResult{}, nil
}

// journalctl is tried at /usr/bin, then /bin.
func TestJournalctlBothPaths(t *testing.T) {
	src := &journaldAt{Live: &Live{Remap: map[string]string{"/var/log": t.TempDir()}}, path: "/bin/journalctl"}
	f := LinuxCollector{}.AuthEvents(context.Background(), src, time.Now(), []string{"/var/log/auth.log"})
	if f.Status != StatusOK || f.Value.FailedBySrc["203.0.113.8"] != 1 || strings.Join(src.ran, ",") != "/usr/bin/journalctl,/bin/journalctl" {
		t.Errorf("%s %q %v ran %v", f.Status, f.Detail, f.Value.FailedBySrc, src.ran)
	}
	for _, argv := range (LinuxCollector{}).Allowlist() {
		if argv[0] == "/bin/journalctl" {
			return
		}
	}
	t.Error("/bin/journalctl not allowlisted")
}

// A secret in a long user name is masked before the name is cut.
func TestSSHUserMaskedBeforeCut(t *testing.T) {
	now := time.Now()
	agg := NewSSHLogins(now.Add(-time.Hour), now, "")
	tok := "gh" + "p_" + strings.Repeat("a1B2", 10)
	agg.Add(now.Add(-time.Minute).UTC().Format(time.RFC3339) + " vm sshd[1]: Invalid user " + strings.Repeat("x", 40) + "-" + tok + " from 203.0.113.9 port 22")
	got := agg.Result()
	if len(got) != 1 || len(got[0].InvalidUsers) != 1 || strings.Contains(got[0].InvalidUsers[0], "a1B2a1B2") {
		t.Errorf("%+v", got)
	}
}
