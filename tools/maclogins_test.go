package tools

import (
	"context"
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// macLog is a Mac whose log show prints lines and exits with code; argv
// is what it was asked to run.
type macLog struct {
	*hostenv.Live
	lines []string
	code  int
	argv  []string
}

func (m *macLog) Info() hostenv.SourceInfo {
	i := m.Live.Info()
	i.GOOS = "darwin"
	return i
}

func (m *macLog) RunLinesUnmasked(_ context.Context, argv []string, fn func(string)) (hostenv.CmdResult, error) {
	m.argv = argv
	for _, l := range m.lines {
		fn(l)
	}
	return hostenv.CmdResult{ExitCode: m.code}, nil
}

// macEvent is one log show --style ndjson line (format.md's shape, values
// made up); uid nil leaves userID out.
func macEvent(at time.Time, image, msg string, pid int, uid any) string {
	e := map[string]any{"processImagePath": image, "senderImagePath": image, "messageType": "Info",
		"timestamp": at.UTC().Format("2006-01-02 15:04:05.000000-0700"), "eventMessage": msg, "processID": pid}
	if uid != nil {
		e["userID"] = uid
	}
	b, _ := json.Marshal(e)
	return string(b)
}

// M0 PR4: on macOS ssh_logins reads sshd's events from the unified log
// (log show --info --style ndjson, by image path) and counts them as on
// Linux, verified: only events logged by root count (VM macos-pr186). A
// user's own sshd (userID 501) and a copy in /tmp named sshd-session are
// not counted, and the source says how many were left out and why.
func TestSSHSummaryMacUnifiedLog(t *testing.T) {
	ip := "198.51.100." + "23"
	now := time.Now().Add(-10 * time.Minute)
	const sess = "/usr/libexec/sshd-session"
	var lines []string
	for range 3 {
		lines = append(lines, macEvent(now, sess, "Failed password for root from "+ip+" port 4000 ssh2", 700, 0))
	}
	lines = append(lines, macEvent(now, sess, "Accepted publickey for root from "+ip+" port 4001 ssh2: ED25519 SHA256:x", 701, 0))
	// Read because --start is an hour early, not counted: before since.
	lines = append(lines, macEvent(time.Now().Add(-90*time.Minute), sess, "Failed password for root from "+ip+" port 3999 ssh2", 699, 0))
	// Forged: a user's own sshd, and a program copied to /tmp.
	lines = append(lines,
		macEvent(now, sess, "Accepted password for root from "+ip+" port 5000 ssh2", 800, 501),
		macEvent(now, "/usr/sbin/sshd", "Failed password for root from "+ip+" port 5001 ssh2", 801, 501),
		macEvent(now, "/private/tmp/sshd-session", "Accepted password for root from "+ip+" port 5002 ssh2", 802, 0))
	m := &macLog{Live: &hostenv.Live{}, lines: lines}
	withHost(t, m)
	since := time.Now().Add(-time.Hour)
	r, err := SSHSummary(context.Background(), &Env{}, since, "")
	if err != nil {
		t.Fatal(err)
	}
	src := r["sources"].([]SSHSource)
	if len(src) != 1 || src[0].Failed != 3 || src[0].Accepted != 1 {
		t.Errorf("sources: %+v", src)
	}
	s, _ := r["source"].(string)
	if r["verified"] != true || r["complete"] != true || !strings.HasPrefix(s, "the unified log") || r["permission"] == true ||
		!strings.Contains(s, hostenv.UnifiedDropNotRoot+" 2") || !strings.Contains(s, hostenv.UnifiedDropNotSSHD+" 1") {
		t.Errorf("summary: %v", r)
	}
	if len(m.argv) == 0 || m.argv[0] != "/usr/bin/log" || m.argv[4] != "ndjson" || m.argv[len(m.argv)-1] != since.Add(-time.Hour).Local().Format("2006-01-02 15:04:05") {
		t.Errorf("ran %q", m.argv)
	}
}

// Outside the admin group log show exits 77: ssh_logins says permission,
// with the reason, not an empty clean-looking result.
func TestSSHSummaryMacNotAdmin(t *testing.T) {
	withHost(t, &macLog{Live: &hostenv.Live{}, code: 77})
	r, err := SSHSummary(context.Background(), &Env{}, time.Now().Add(-time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	e, _ := r["error"].(string)
	if r["permission"] != true || r["complete"] != false || !strings.Contains(e, "admin group") {
		t.Errorf("not admin: %v", r)
	}
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), `"permission":true`) {
		t.Errorf("result: %s", b)
	}
}

// Any other failure of log show (a predicate it rejects: exit 64) is an
// error, not an empty, complete count; and no root advice.
func TestSSHSummaryMacLogFails(t *testing.T) {
	withHost(t, &macLog{Live: &hostenv.Live{}, code: 64})
	r, err := SSHSummary(context.Background(), &Env{}, time.Now().Add(-time.Hour), "")
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := r["error"].(string); r["complete"] != false || !strings.Contains(e, "exit status 64") || r["permission"] == true {
		t.Errorf("log show failed: %v", r)
	}
}

// On a real Mac the command runs through the product's allowlist (the CI
// macos job; a work Mac prints only the result's shape).
func TestSSHSummaryMacLive(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	r, err := SSHSummary(context.Background(), &Env{}, time.Now().Add(-10*time.Minute), "")
	if err != nil {
		t.Fatal(err)
	}
	e, _ := r["error"].(string)
	if !strings.HasPrefix(r["source"].(string), "the unified log") || (e != "" && r["permission"] != true) {
		t.Errorf("source %v, error %d bytes, permission %v", r["source"], len(e), r["permission"])
	}
}
