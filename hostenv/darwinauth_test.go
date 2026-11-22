package hostenv

import (
	"strings"
	"testing"
	"time"
)

// M0 PR4: log show --style syslog lines (shapes from
// vm-acceptance/results/macos-m0-pr4/format.md, values made up) become
// auth.log lines the Linux regexes and ParseLogTime read; the header, the
// continuation lines and the libraries' lines count for nothing.
func TestUnifiedToAuthLine(t *testing.T) {
	ip := "203.0.113." + "7"
	at := "2026-11-22 03:46:01.123456+0000"
	head := at + "  localhost sshd-session[812]: "
	login := NewSSHLogins(time.Date(2026, 11, 22, 3, 0, 0, 0, time.UTC), time.Date(2026, 11, 22, 4, 0, 0, 0, time.UTC), "")
	for _, l := range []string{
		"Timestamp                       (process)[PID]    ",
		head + "Accepted publickey for alice from " + ip + " port 50123 ssh2: ED25519 SHA256:abc",
		head + "Failed password for alice from " + ip + " port 50124 ssh2",
		head + "Invalid user nosuchuser from " + ip + " port 50125",
		head + "Failed password for invalid user nosuchuser from " + ip + " port 50125 ssh2",
		head + "Connection closed by authenticating user alice " + ip + " port 50126 [preauth]",
		head + "(libpam.2.dylib) in pam_sm_authenticate(): OpenDirectory - The authtok is incorrect.",
		"\tsecond line of a library message",
		"2026-11-22 03:46:02.000001+0000  localhost sshd[90]: Failed password for root from " + ip + " port 1 ssh2", // older macOS
	} {
		if a, ok := UnifiedToAuthLine(l); ok {
			if !strings.HasPrefix(a, "2026-11-22T03:46:0") {
				t.Errorf("rewritten: %q", a)
			}
			if _, ok := ParseLogTime(a, time.Now()); !ok {
				t.Errorf("no time in %q", a)
			}
			login.Add(a)
		} else if strings.Contains(l, "sshd") {
			t.Errorf("not rewritten: %q", l)
		}
	}
	src, _ := MaxLogins(login)
	if len(src) != 1 || src[0].IP != ip || src[0].Accepted != 1 || src[0].Failed != 3 || src[0].InvalidUser != 1 {
		t.Errorf("counted: %+v", src)
	}
}

// The unified log command is allowlisted with its time slot only, and
// names the program by its SIP-protected image paths, never by process.
func TestUnifiedSSHArgvAllowed(t *testing.T) {
	r, err := NewRunner(DarwinCollector{}.Allowlist())
	if err != nil {
		t.Fatal(err)
	}
	argv := append([]string(nil), UnifiedSSHArgv...)
	argv[len(argv)-1] = "2026-11-22 11:00:00"
	if !r.Allowed(argv) {
		t.Errorf("not allowed: %q", argv)
	}
	argv[len(argv)-1] = "1970-01-01 00:00:00; rm"
	if r.Allowed(argv) {
		t.Errorf("a non-time --start was allowed")
	}
	p := UnifiedSSHArgv[6]
	if strings.Contains(p, "process ==") || !strings.Contains(p, `processImagePath == "/usr/libexec/sshd-session"`) || !strings.Contains(p, `senderImagePath == "/usr/sbin/sshd"`) {
		t.Errorf("predicate: %s", p)
	}
	if UnifiedSSHArgv[0] != "/usr/bin/log" || UnifiedSSHArgv[2] != "--info" {
		t.Errorf("argv: %q", UnifiedSSHArgv[:3])
	}
}
