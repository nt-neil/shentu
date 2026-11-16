package tools

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

// block_ip refuses an IP whose SSH login events may be forged, unless the
// operator overrides: see loginGate.
func TestBlockIPUnverifiedLoginGate(t *testing.T) {
	oldS, oldT := loginSummary, textLogins
	t.Cleanup(func() { loginSummary, textLogins = oldS, oldT })
	ip := net.ParseIP("203.0.113.77")
	text := 0 // events for ip in the text logs
	textLogins = func(_ *Env, only string) (int, []string, []string) {
		if only != ip.String() {
			t.Errorf("text logs asked for %q", only)
		}
		return text, nil, nil
	}
	summary := func(verified, complete bool, srcs ...SSHSource) {
		loginSummary = func(_ context.Context, _ *Env, since time.Time, only string) (map[string]any, error) {
			if back := time.Since(since); only != ip.String() || back < 23*time.Hour || back > 721*time.Hour {
				t.Errorf("asked for %q since %v", only, since)
			}
			return map[string]any{"verified": verified, "complete": complete, "source": "/var/log/secure", "sources": srcs}, nil
		}
	}
	gate := func(override bool) error { return loginGate(context.Background(), &Env{}, ip, override) }
	forged := SSHSource{IP: ip.String(), Failed: 15}
	for _, c := range []struct {
		name               string
		verified, complete bool
		srcs               []SSHSource
		text               int
		refuse             bool
	}{
		{"text logs only (unverified summary)", false, true, []SSHSource{forged}, 15, true},
		{"IPv4-mapped in a forged line", false, true, []SSHSource{{IP: "::ffff:203.0.113.77", Failed: 15}}, 15, true},
		// journald has sshd entries of other IPs in the long window, none for
		// this one; the forged ones are in the text logs, which ssh_logins
		// read for a span when journald was empty.
		{"journald silent on the IP, text logs not", true, true, nil, 15, true},
		{"journald confirms the IP", true, true, []SSHSource{{IP: ip.String(), Failed: 3}}, 15, false},
		{"no login events anywhere", true, true, nil, 0, false},
		{"logs not read in full", true, false, nil, 0, true},
	} {
		summary(c.verified, c.complete, c.srcs...)
		text = c.text
		err := gate(false)
		if (err != nil) != c.refuse || err != nil && !strings.Contains(err.Error(), "override_unverified") {
			t.Errorf("%s: %v", c.name, err)
		}
		if err := gate(true); err != nil {
			t.Errorf("%s, override: %v", c.name, err)
		}
	}
	loginSummary = func(context.Context, *Env, time.Time, string) (map[string]any, error) { return nil, errors.New("x") }
	if err := gate(false); err == nil || !strings.Contains(err.Error(), "could not be read") {
		t.Errorf("summary failed: %v", err)
	}
}

// The override is visible in the preview the operator confirms.
func TestBlockIPOverrideInPreview(t *testing.T) {
	var a ipArgs
	if err := json.Unmarshal([]byte(`{"ip":"203.0.113.77","reason":"x","override_unverified":true}`), &a); err != nil || !a.OverrideUnverified {
		t.Fatalf("%+v %v", a, err)
	}
	if !strings.Contains(blockIP.Description+string(blockIP.Params), "override_unverified") {
		t.Error("override_unverified not in the tool's parameters")
	}
	// The gate's reach is said: SSH login evidence only.
	skill, err := os.ReadFile("../skills/ssh-bruteforce/SKILL.md")
	for what, text := range map[string]string{"tool description": blockIP.Description, "ssh-bruteforce skill": string(skill)} {
		if err != nil || !strings.Contains(text, "SSH login evidence only") {
			t.Errorf("%s does not say the check covers SSH login evidence only (%v)", what, err)
		}
	}
}

// The last day is asked first; the month only when the day has no events
// for the IP and was read in full.
func TestBlockIPGateDayFirst(t *testing.T) {
	oldS, oldT := loginSummary, textLogins
	t.Cleanup(func() { loginSummary, textLogins = oldS, oldT })
	textLogins = func(*Env, string) (int, []string, []string) { return 0, nil, nil }
	ip := net.ParseIP("203.0.113.77")
	var asked []time.Duration
	srcs := []SSHSource{{IP: ip.String(), Failed: 3}}
	loginSummary = func(_ context.Context, _ *Env, since time.Time, _ string) (map[string]any, error) {
		asked = append(asked, time.Since(since).Round(time.Hour))
		return map[string]any{"verified": true, "complete": true, "sources": srcs}, nil
	}
	if err := loginGate(context.Background(), &Env{}, ip, false); err != nil || len(asked) != 1 || asked[0] != 24*time.Hour {
		t.Errorf("events in the day: %v %v", err, asked)
	}
	asked, srcs = nil, nil
	if err := loginGate(context.Background(), &Env{}, ip, false); err != nil || len(asked) != 2 || asked[1] != 720*time.Hour {
		t.Errorf("none in the day: %v %v", err, asked)
	}
}

// Through the real SSHSummary: no journald (no commands may run) and an
// auth log this user cannot read. SSHSummary returns no error then, only
// complete=false; the gate refuses.
func TestBlockIPGateUnreadableLogsRealSummary(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs a file this user cannot read, and the Linux login path")
	}
	dir := t.TempDir()
	auth := filepath.Join(dir, "auth.log")
	os.WriteFile(auth, []byte("Nov 14 10:00:00 vm sshd[1]: Failed password for root from 203.0.113.77 port 22 ssh2\n"), 0o600)
	os.Chmod(auth, 0)
	t.Cleanup(func() { os.Chmod(auth, 0o600) })
	noCmds, _ := hostenv.NewRunner(nil)
	prev := hostSource
	hostSource = func() hostenv.Source { return &hostenv.Live{Runner: noCmds, Remap: map[string]string{"/var/log": dir}} }
	t.Cleanup(func() { hostSource = prev })
	env := &Env{LogPaths: []string{"/var/log/auth.log"}}
	r, err := SSHSummary(context.Background(), env, time.Now().Add(-24*time.Hour), "203.0.113.77")
	if c, _ := r["complete"].(bool); err != nil || c {
		t.Fatalf("SSHSummary: complete %v, err %v", r["complete"], err)
	}
	gerr := loginGate(context.Background(), env, net.ParseIP("203.0.113.77"), false)
	if gerr == nil || !strings.Contains(gerr.Error(), "could not be read in full") {
		t.Errorf("unreadable logs: %v", gerr)
	}
	if err := loginGate(context.Background(), env, net.ParseIP("203.0.113.77"), true); err != nil {
		t.Errorf("override: %v", err)
	}
}

// #80 review N-2, through the real SSHSummary: no journald, and a forged
// auth.log line dated 40 days back, which ssh_logins could show with a long
// since_hours. The gate reads the text logs whatever the lines' dates say,
// and refuses.
func TestBlockIPGateOldForgedLine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Linux login path")
	}
	dir := t.TempDir()
	old := time.Now().Add(-40 * 24 * time.Hour).UTC().Format(time.RFC3339)
	os.WriteFile(filepath.Join(dir, "auth.log"), []byte(old+" vm sshd[1]: Failed password for root from 203.0.113.77 port 22 ssh2\n"), 0o600)
	noCmds, _ := hostenv.NewRunner(nil)
	prev := hostSource
	hostSource = func() hostenv.Source { return &hostenv.Live{Runner: noCmds, Remap: map[string]string{"/var/log": dir}} }
	t.Cleanup(func() { hostSource = prev })
	env := &Env{LogPaths: []string{"/var/log/auth.log"}}
	err := loginGate(context.Background(), env, net.ParseIP("203.0.113.77"), false)
	if err == nil || !strings.Contains(err.Error(), "may be forged") {
		t.Errorf("40-day-old forged line: %v", err)
	}
	// ssh_logins looks no further back than the gate.
	out, err := sshLogins.Run(context.Background(), env, json.RawMessage(`{"since_hours":2000,"ip":"203.0.113.77"}`))
	r, _ := out.(map[string]any)
	if since, _ := r["since"].(time.Time); err != nil || time.Since(since) > 721*time.Hour {
		t.Errorf("ssh_logins since_hours 2000: since %v, err %v", r["since"], err)
	}
}

// A text auth log that cannot be read is not passed over: the gate refuses.
func TestBlockIPGateUnreadableTextLog(t *testing.T) {
	oldS, oldT := loginSummary, textLogins
	t.Cleanup(func() { loginSummary, textLogins = oldS, oldT })
	loginSummary = func(context.Context, *Env, time.Time, string) (map[string]any, error) {
		return map[string]any{"verified": true, "complete": true}, nil
	}
	textLogins = func(*Env, string) (int, []string, []string) { return 0, nil, []string{"/var/log/auth.log.1 (permission_denied)"} }
	err := loginGate(context.Background(), &Env{}, net.ParseIP("203.0.113.77"), false)
	if err == nil || !strings.Contains(err.Error(), "could not all be read") {
		t.Errorf("unreadable text log: %v", err)
	}
}

// journald confirming the IP's logins is enough: an auth.log this user
// cannot read (in systemd-journal, not adm) does not refuse the block. With
// no journald events for the IP it still does.
func TestBlockIPGateJournaldFirst(t *testing.T) {
	oldS, oldT := loginSummary, textLogins
	t.Cleanup(func() { loginSummary, textLogins = oldS, oldT })
	ip := net.ParseIP("203.0.113.77")
	read := false
	textLogins = func(*Env, string) (int, []string, []string) {
		read = true
		return 0, nil, []string{"/var/log/auth.log (permission_denied)"}
	}
	srcs := []SSHSource{{IP: ip.String(), Failed: 9}}
	loginSummary = func(context.Context, *Env, time.Time, string) (map[string]any, error) {
		return map[string]any{"verified": true, "complete": true, "sources": srcs}, nil
	}
	if err := loginGate(context.Background(), &Env{}, ip, false); err != nil || read {
		t.Errorf("journald has the IP, auth.log unreadable: %v (text logs read: %v)", err, read)
	}
	srcs = nil
	if err := loginGate(context.Background(), &Env{}, ip, false); err == nil || !strings.Contains(err.Error(), "could not all be read") {
		t.Errorf("journald without the IP, auth.log unreadable: %v", err)
	}
}

// VM acceptance N2: journald has sshd entries, none for the IP, and auth.log
// has a forged line for it. The refusal names the text log the events are
// in, not the summary's source ("journald").
func TestBlockIPGateNamesTextLog(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Linux login path")
	}
	dir := t.TempDir()
	now := time.Now().UTC().Format(time.RFC3339)
	os.WriteFile(filepath.Join(dir, "auth.log"), []byte(now+" vm sshd[1]: Failed password for root from 203.0.113.77 port 22 ssh2\n"), 0o600)
	os.WriteFile(filepath.Join(dir, "secure"), []byte(now+" vm sshd[2]: Failed password for root from 198.51.100.4 port 22 ssh2\n"), 0o600)
	noCmds, _ := hostenv.NewRunner(nil)
	prevH, prevS := hostSource, loginSummary
	hostSource = func() hostenv.Source { return &hostenv.Live{Runner: noCmds, Remap: map[string]string{"/var/log": dir}} }
	loginSummary = func(context.Context, *Env, time.Time, string) (map[string]any, error) {
		return map[string]any{"verified": true, "complete": true, "source": "journald", "sources": []SSHSource(nil)}, nil
	}
	t.Cleanup(func() { hostSource, loginSummary = prevH, prevS })
	env := &Env{LogPaths: []string{"/var/log/auth.log", "/var/log/secure"}}
	err := loginGate(context.Background(), env, net.ParseIP("203.0.113.77"), false)
	if err == nil || !strings.Contains(err.Error(), "may be forged") || !strings.Contains(err.Error(), "(/var/log/auth.log)") ||
		strings.Contains(err.Error(), "journald)") || strings.Contains(err.Error(), "secure") {
		t.Errorf("forged auth.log line, journald without the IP: %v", err)
	}
}
