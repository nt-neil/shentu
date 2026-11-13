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

// block_ip refuses an IP whose SSH logins come only from text logs anyone on
// the host can write to (verified=false), unless the operator overrides.
func TestBlockIPUnverifiedLoginGate(t *testing.T) {
	old := loginSummary
	t.Cleanup(func() { loginSummary = old })
	ip := net.ParseIP("203.0.113.77")
	summary := func(verified bool, srcs ...SSHSource) {
		loginSummary = func(_ context.Context, _ *Env, since time.Time, only string) (map[string]any, error) {
			if only != ip.String() || time.Since(since) < 23*time.Hour {
				t.Errorf("asked for %q since %v", only, since)
			}
			return map[string]any{"verified": verified, "source": "/var/log/secure", "sources": srcs}, nil
		}
	}
	forged := SSHSource{IP: ip.String(), Failed: 15}
	summary(false, forged)
	err := loginGate(context.Background(), &Env{}, ip, false)
	if err == nil || !strings.Contains(err.Error(), "refusing to block 203.0.113.77") || !strings.Contains(err.Error(), "override_unverified") {
		t.Errorf("unverified, no override: %v", err)
	}
	if err := loginGate(context.Background(), &Env{}, ip, true); err != nil {
		t.Errorf("unverified, override: %v", err)
	}
	summary(true, forged)
	if err := loginGate(context.Background(), &Env{}, ip, false); err != nil {
		t.Errorf("journald: %v", err)
	}
	summary(false) // the IP has no login events: blocked for something else
	if err := loginGate(context.Background(), &Env{}, ip, false); err != nil {
		t.Errorf("no login events: %v", err)
	}
	// The same source written as an IPv4-mapped address in a forged line.
	summary(false, SSHSource{IP: "::ffff:203.0.113.77", Failed: 15})
	if err := loginGate(context.Background(), &Env{}, ip, false); err == nil {
		t.Error("IPv4-mapped source not matched")
	}
	// Logins that cannot be read at all: it cannot tell, so it refuses
	// unless overridden.
	loginSummary = func(context.Context, *Env, time.Time, string) (map[string]any, error) { return nil, errors.New("x") }
	if err := loginGate(context.Background(), &Env{}, ip, false); err == nil || !strings.Contains(err.Error(), "could not be read") {
		t.Errorf("summary failed: %v", err)
	}
	if err := loginGate(context.Background(), &Env{}, ip, true); err != nil {
		t.Errorf("summary failed, override: %v", err)
	}
	// The window covers any span ssh_logins may have reported on, up to the
	// longest block.
	loginSummary = func(_ context.Context, _ *Env, since time.Time, _ string) (map[string]any, error) {
		if time.Since(since) < 719*time.Hour {
			t.Errorf("window %v", time.Since(since))
		}
		return map[string]any{"verified": true}, nil
	}
	loginGate(context.Background(), &Env{}, ip, false)
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
