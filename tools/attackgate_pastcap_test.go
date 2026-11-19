package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/detect"
)

// v0.4.1 gate fix: an address past an unverified group's listed ones
// (MaxGroupIPs) is refused as a listed one is, from Telegram too.

// pastCapState: 12 unverified L2 attempts from 203.0.113.1 to .12 (.12
// logged IPv4-mapped); overflow: merged into an overflow group, past
// MaxGroups, as the patrol evicts.
func pastCapState(t *testing.T, overflow bool) {
	t.Helper()
	now := time.Now()
	a := &detect.Attacks{} // as attacks.json loads: the campaign index too
	if err := json.Unmarshal([]byte(`{"version":1,"groups":{},"ips":{},"overflow":{}}`), a); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 12; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		if i == 12 {
			ip = "::ffff:203.0.113.12"
		}
		a.Add(detect.Attempt{Entry: "code:marker:a.php:1", Level: detect.LevelPayload, Severity: "high", IP: ip, Verified: false, Reason: "marker"}, now)
	}
	if overflow { // verified groups of other entries push the unverified one out
		for i := 0; len(a.Overflow) == 0; i++ {
			a.Add(detect.Attempt{Entry: fmt.Sprintf("code:marker:f%d.php:1", i), Level: detect.LevelPayload, Severity: "high", IP: "192.0.2.1", Verified: true}, now)
		}
	}
	old := attackState
	t.Cleanup(func() { attackState = old })
	attackState = func() (*detect.Attacks, error) { return a, nil }
}

func TestBlockIPPastCapFromTelegram(t *testing.T) {
	pastCapState(t, false)
	args, _ := json.Marshal(map[string]any{"ip": "203.0.113.11", "reason": "marker"})
	if _, err := blockIP.Run(context.Background(), &Env{Remote: true}, args); err == nil || !strings.Contains(err.Error(), "cannot be believed") {
		t.Errorf("past the cap, from Telegram: %v", err)
	}
}

func TestAttackGatePastCap(t *testing.T) {
	for _, c := range []struct {
		name     string
		overflow bool
		ip       string
		override bool
		v        gateVerdict
		say      string
	}{
		{"past the cap", false, "203.0.113.11", false, gateRefuse, "cannot be believed"},
		// Expected: a clean neighbour in the /24 may be one of the
		// addresses past the list; it is refused with them.
		{"a neighbour never seen", false, "203.0.113.200", false, gateRefuse, "past those listed"},
		{"logged IPv4-mapped", false, "203.0.113.12", false, gateRefuse, "cannot be believed"},
		{"override on the server: its logins decide", false, "203.0.113.11", true, gateNone, ""},
		{"another network", false, "198.51.100.7", false, gateNone, ""},
		{"merged into an overflow group", true, "203.0.113.11", false, gateRefuse, "overflow"},
		{"merged, override: not for a summary", true, "203.0.113.11", true, gateRefuse, "overflow"},
		{"merged, logged IPv4-mapped", true, "::ffff:203.0.113.12", false, gateRefuse, "overflow"},
		{"merged, a neighbour never seen", true, "203.0.113.200", false, gateNone, ""},
	} {
		pastCapState(t, c.overflow)
		v, err := attackGate(net.ParseIP(c.ip), c.override)
		if v != c.v || (err != nil) != (c.say != "") || err != nil && !strings.Contains(err.Error(), c.say) {
			t.Errorf("%s: %v %v", c.name, v, err)
		}
	}
}

// An address its verified SSH logins condemn is still blocked: a refusal
// on attempts falls back to them (blockGate), as for a listed one.
func TestBlockGatePastCapVerifiedLogins(t *testing.T) {
	pastCapState(t, false)
	oldS, oldT := loginSummary, textLogins
	t.Cleanup(func() { loginSummary, textLogins = oldS, oldT })
	textLogins = func(*Env, string) (int, []string, []string) { return 0, nil, nil }
	loginSummary = func(context.Context, *Env, time.Time, string) (map[string]any, error) {
		return map[string]any{"complete": true, "verified": true, "source": "journald", "sources": []SSHSource{{IP: "203.0.113.11", Failed: 40}}}, nil
	}
	if err := blockGate(context.Background(), &Env{Remote: true}, net.ParseIP("203.0.113.11"), false); err != nil {
		t.Errorf("verified SSH logins: %v", err)
	}
	loginSummary = func(context.Context, *Env, time.Time, string) (map[string]any, error) {
		return map[string]any{"complete": true, "verified": true, "source": "journald"}, nil
	}
	if err := blockGate(context.Background(), &Env{Remote: true}, net.ParseIP("203.0.113.11"), false); err == nil {
		t.Error("no SSH logins: blocked past the cap")
	}
}
