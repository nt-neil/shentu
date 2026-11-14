package tools

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// block_ip refuses an IP whose SSH login events may be forged, unless the
// operator overrides: see loginGate.
func TestBlockIPUnverifiedLoginGate(t *testing.T) {
	oldS, oldT := loginSummary, textLogins
	t.Cleanup(func() { loginSummary, textLogins = oldS, oldT })
	ip := net.ParseIP("203.0.113.77")
	text := 0 // events for ip in the text logs
	textLogins = func(_ *Env, since time.Time, only string) int {
		if only != ip.String() || time.Since(since) < 719*time.Hour {
			t.Errorf("text logs asked for %q since %v", only, since)
		}
		return text
	}
	summary := func(verified, complete bool, srcs ...SSHSource) {
		loginSummary = func(_ context.Context, _ *Env, since time.Time, only string) (map[string]any, error) {
			if only != ip.String() || time.Since(since) < 719*time.Hour {
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
}
