package hostenv

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// unifiedEvent is one log show --style ndjson line in the shape of
// vm-acceptance/results/macos-m0-pr4/format.md (values made up); uid nil
// leaves userID out.
func unifiedEvent(at, image, sender, msg string, pid int, uid any) string {
	e := map[string]any{"timezoneName": "", "messageType": "Info", "eventType": "logEvent", "formatString": "%.500s",
		"processImagePath": image, "senderImagePath": sender, "timestamp": at, "eventMessage": msg, "processID": pid,
		"subsystem": "", "category": ""}
	if uid != nil {
		e["userID"] = uid
	}
	b, _ := json.Marshal(e)
	return string(b)
}

// M0 PR4, macos-pr186: ndjson events become auth.log lines the Linux
// regexes and ParseLogTime read, only sshd's own written by root; every
// other one is dropped with its word: a user's own sshd (userID 501),
// a copy in /tmp, the libraries' lines, a broken event.
func TestUnifiedToAuthLine(t *testing.T) {
	ip := "203.0.113." + "7"
	at := "2026-11-22 03:46:01.123456+0000"
	const sess, sshd = "/usr/libexec/sshd-session", "/usr/sbin/sshd"
	login := NewSSHLogins(time.Date(2026, 11, 22, 3, 0, 0, 0, time.UTC), time.Date(2026, 11, 22, 4, 0, 0, 0, time.UTC), "")
	kept := []string{
		unifiedEvent(at, sess, sess, "Accepted publickey for alice from "+ip+" port 50123 ssh2: ED25519 SHA256:abc", 812, 0),
		unifiedEvent(at, sess, sess, "Failed password for alice from "+ip+" port 50124 ssh2", 812, 0),
		unifiedEvent(at, sess, sess, "Invalid user nosuchuser from "+ip+" port 50125", 812, 0),
		unifiedEvent(at, sess, sess, "Failed password for invalid user nosuchuser from "+ip+" port 50125 ssh2", 812, 0),
		unifiedEvent(at, sess, sess, "Connection closed by authenticating user alice "+ip+" port 50126 [preauth]", 812, 0),
		unifiedEvent("2026-11-22 03:46:02.000001+0000", sshd, sshd, "Failed password for root from "+ip+" port 1 ssh2", 90, 0), // older macOS
	}
	other := "198.51.100." + "9"
	dropped := map[string]string{
		unifiedEvent(at, sess, sess, "Accepted publickey for alice from "+other+" port 1 ssh2: ED25519 SHA256:x", 900, 501):                         UnifiedDropNotRoot,
		unifiedEvent(at, sshd, sshd, "Accepted password for root from "+other+" port 2 ssh2", 901, 501):                                             UnifiedDropNotRoot,
		unifiedEvent(at, sess, sess, "Accepted password for root from "+other+" port 3 ssh2", 902, nil):                                             UnifiedDropNoUserID,
		unifiedEvent(at, "/private/tmp/sshd-session", "/private/tmp/sshd-session", "Accepted password for root from "+other+" port 4 ssh2", 903, 0): UnifiedDropNotSSHD,
		unifiedEvent(at, sess, "/usr/lib/libpam.2.dylib", "in pam_sm_authenticate(): OpenDirectory - The authtok is incorrect.", 812, 0):            UnifiedDropNotSSHD,
		unifiedEvent("yesterday", sess, sess, "Failed password for root from "+other+" port 5 ssh2", 904, 0):                                        UnifiedDropBadEvent,
		`{"timestamp": "2026-11-22 03:46:01.123456+0000", "eventMessage": `:                                                                         UnifiedDropBadEvent,
		`{"count":7,"finished":1}`: unifiedEnd,          // log show's closing line: not an event (N-186r-1)
		`{"count":7,"finished":0}`: UnifiedDropBadEvent, // one that says it did not finish
	}
	for _, l := range kept {
		a, drop := UnifiedToAuthLine(l)
		if drop != "" || !strings.HasPrefix(a, "2026-11-22T03:46:0") {
			t.Errorf("kept %q: %q drop %q", l, a, drop)
			continue
		}
		if _, ok := ParseLogTime(a, time.Now()); !ok {
			t.Errorf("no time in %q", a)
		}
		login.Add(a)
	}
	for l, want := range dropped {
		if a, drop := UnifiedToAuthLine(l); a != "" || drop != want {
			t.Errorf("%q: %q drop %q, want %q", l, a, drop, want)
		} else {
			login.Add(a)
		}
	}
	if a, drop := UnifiedToAuthLine(""); a != "" || drop != "" {
		t.Errorf("empty line: %q %q", a, drop)
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
	if UnifiedSSHArgv[0] != "/usr/bin/log" || UnifiedSSHArgv[2] != "--info" || UnifiedSSHArgv[4] != "ndjson" {
		t.Errorf("argv: %q", UnifiedSSHArgv[:5])
	}
}
