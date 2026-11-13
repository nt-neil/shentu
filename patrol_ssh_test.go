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
