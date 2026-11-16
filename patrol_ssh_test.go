package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/tools"
)

// Login logs that could not be read in full are listed as not checked, so an
// hourly report with no SSH finding is not read as "no failed logins".
func TestSSHFindingsIncompleteIsNotChecked(t *testing.T) {
	for _, c := range []struct {
		name string
		r    map[string]any
		err  error
		want string // "" when nothing is listed
	}{
		{"read in full", map[string]any{"complete": true, "verified": true, "sources": []tools.SSHSource{}}, nil, ""},
		{"nothing readable", map[string]any{"complete": false, "verified": false, "source": "", "sources": []tools.SSHSource{},
			"error": "open /var/log/secure: permission denied"}, nil, "permission denied"},
		{"cut short", map[string]any{"complete": false, "verified": true, "sources": []tools.SSHSource{}}, nil, "cut short or could not be read"},
		{"summary failed", nil, errors.New("journalctl: exit 1"), "journalctl: exit 1"},
	} {
		_, why := sshFindings(c.r, c.err, 5)
		if c.want == "" && why != "" || c.want != "" && (!strings.Contains(why, "Not checked") || !strings.Contains(why, c.want)) {
			t.Errorf("%s: %q", c.name, why)
		}
	}
	// Sources over the threshold are still reported when the logs are partial.
	r := map[string]any{"complete": false, "verified": true, "sources": []tools.SSHSource{{IP: "203.0.113.9", Failed: 7}}}
	if f, why := sshFindings(r, nil, 5); len(f) != 1 || f[0].Key != "ssh:203.0.113.9" || why == "" {
		t.Errorf("partial with a source: %+v %q", f, why)
	}
}

// The reason given is what kept the logs from counting, and root is
// advised only when rights were missing (review N-3): a quiet host whose
// journal has no sshd entry and no text log, and macOS, which has no sshd
// log Shentu reads, are not helped by root.
func TestSSHFindingsNotCheckedReason(t *testing.T) {
	quiet := "journald (no sshd entries in the ssh, sshd, ssh@ or sshd@ units, and no text auth log: journald may not keep them, as with Storage=none)"
	for _, c := range []struct {
		name     string
		r        map[string]any
		want     []string
		root, lb bool // advises root; says the counts are a lower bound
	}{
		{"quiet host", map[string]any{"complete": false, "verified": false, "source": quiet}, []string{"Not checked in full", "no sshd entries"}, false, true},
		{"no rights", map[string]any{"complete": false, "verified": false, "permission": true,
			"source": "none (journald has no sshd entries; /var/log/auth.log (permission_denied) unreadable)", "error": "open /var/log/auth.log: permission denied"},
			[]string{"Not checked in full", "permission denied"}, true, true},
		{"macOS", map[string]any{"complete": false, "verified": false, "unsupported": true,
			"source": "none: Shentu has no sshd log source on macOS (it reads journald and the text auth logs, which macOS does not keep)"},
			[]string{"Not checked: SSH logins", "no sshd log source on macOS"}, false, false},
	} {
		_, why := sshFindings(c.r, nil, 5)
		for _, w := range c.want {
			if !strings.Contains(why, w) {
				t.Errorf("%s: %q lacks %q", c.name, why, w)
			}
		}
		if strings.Contains(why, "as root") != c.root || strings.Contains(why, "lower bound") != c.lb {
			t.Errorf("%s: root %v, lower bound %v: %q", c.name, c.root, c.lb, why)
		}
		if strings.Contains(why, "allowlist") {
			t.Errorf("%s: internal error shown: %q", c.name, why)
		}
	}
}
