package tools

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/detect"
)

// v0.4.1, #108 review 1: from a chat channel (Telegram) block_ip is
// refused unless the address has evidence shentu verified: a verified L2
// or L3 group listing it, or SSH login events sshd itself logged.

// remoteLogins makes the login summary show ip with failed logins, verified
// (journald, sshd's own: the package's sshdJournal stub) or none at all.
func remoteLogins(t *testing.T, ip string, failed int) {
	t.Helper()
	oldS, oldT := loginSummary, textLogins
	t.Cleanup(func() { loginSummary, textLogins = oldS, oldT })
	textLogins = func(*Env, string) (int, []string, []string) { return 0, nil, nil }
	loginSummary = func(context.Context, *Env, time.Time, string) (map[string]any, error) {
		r := map[string]any{"complete": true, "verified": true, "source": "journald"}
		if failed > 0 {
			r["sources"] = []SSHSource{{IP: ip, Failed: failed}}
		}
		return r, nil
	}
}

func TestBlockGateRemote(t *testing.T) {
	remote := &Env{Remote: true}
	for _, c := range []struct {
		name   string
		groups []*detect.Group
		ip     string
		logins int
		ok     bool
	}{
		{"verified L2 listing it", []*detect.Group{grp("a", "203.0.113.0/24", "L2", true, "203.0.113.12")}, "203.0.113.12", 0, true},
		{"verified SSH brute force, no group", nil, "203.0.113.12", 40, true},
		{"no evidence at all", nil, "203.0.113.12", 0, false},
		// N-1: an unverified group notified, then evicted: gone from the state.
		{"its group evicted", []*detect.Group{grp("b", "198.51.100.0/24", "L2", false, "198.51.100.7")}, "203.0.113.11", 0, false},
		// N-2: an unverified group's source written another way.
		{"logged with a leading zero", []*detect.Group{grp("a", "203.0.113.012", "L2", false, "203.0.113.012")}, "203.0.113.12", 0, false},
		{"logged with a port", []*detect.Group{grp("a", "203.0.113.12:51234", "L2", false, "203.0.113.12:51234")}, "203.0.113.12", 0, false},
		{"logged in brackets", []*detect.Group{grp("a", "[203.0.113.12]", "L2", false, "[203.0.113.12]")}, "203.0.113.12", 0, false},
		{"logged with a zone", []*detect.Group{grp("a", "2001:db8::12%0", "L2", false, "2001:db8::12%0")}, "2001:db8::12", 0, false},
		{"verified L1 only", []*detect.Group{grp("a", "203.0.113.0/24", "L1", true, "203.0.113.12")}, "203.0.113.12", 0, false},
		{"unverified L2, verified SSH brute force", []*detect.Group{grp("a", "203.0.113.0/24", "L2", false, "203.0.113.12")}, "203.0.113.12", 40, true},
	} {
		gateState(t, c.groups...)
		remoteLogins(t, c.ip, c.logins)
		err := blockGate(context.Background(), remote, net.ParseIP(c.ip), false)
		if (err == nil) != c.ok || err != nil && !strings.Contains(err.Error(), "shentu chat") {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// On the server, a source written another way is read loosely: enough
// to refuse on, never to allow.
func TestAttackGateLooseForms(t *testing.T) {
	for _, c := range []struct {
		name   string
		logged string
		ip     string
		v      gateVerdict
	}{
		{"a leading zero, decimal", "203.0.113.012", "203.0.113.12", gateRefuse},
		{"a leading zero, octal", "203.0.113.014", "203.0.113.12", gateRefuse},
		{"a port", "203.0.113.12:51234", "203.0.113.12", gateRefuse},
		{"brackets and a port", "[2001:db8::12]:443", "2001:db8::12", gateRefuse},
		{"a zone", "2001:db8::12%eth0", "2001:db8::12", gateRefuse},
		{"IPv4-compatible", "::203.0.113.12", "203.0.113.12", gateRefuse},
		{"NAT64", "64:ff9b::cb00:710c", "203.0.113.12", gateRefuse},
		{"another address", "203.0.113.13", "203.0.113.12", gateNone},
	} {
		gateState(t, grp("a", c.logged, "L2", false, c.logged))
		if v, _ := attackGate(net.ParseIP(c.ip), false); v != c.v {
			t.Errorf("%s: %v", c.name, v)
		}
	}
	// A verified group listing it only in another form does not allow.
	gateState(t, grp("a", "203.0.113.012", "L2", true, "203.0.113.012"))
	if v, err := attackGate(net.ParseIP("203.0.113.12"), false); v == gateAllow || err == nil {
		t.Errorf("verified, another form: %v %v", v, err)
	}
	gateState(t, grp("a", "203.0.113.0/24", "L2", true, "203.0.113.12"))
	if v, _ := attackGate(net.ParseIP("203.0.113.12"), false); v != gateAllow {
		t.Errorf("verified, its own form: %v", v)
	}
}
