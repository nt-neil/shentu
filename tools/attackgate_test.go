package tools

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/detect"
)

// The login gate's tests replace the summary; sshd's own journal lines
// confirm by default (TestLoginGateSSHDItself says otherwise).
func init() {
	sshdJournal = func(context.Context, time.Time, string) (int, error) { return 1, nil }
}

// Review 1 of #91 (S-4): journald's SSH events count only when sshd itself
// wrote them; a logger line in sshd's unit does not.
func TestLoginGateSSHDItself(t *testing.T) {
	ip := net.ParseIP("198.51.100.7")
	oldS, oldT, oldJ := loginSummary, textLogins, sshdJournal
	t.Cleanup(func() { loginSummary, textLogins, sshdJournal = oldS, oldT, oldJ })
	loginSummary = func(context.Context, *Env, time.Time, string) (map[string]any, error) {
		return map[string]any{"complete": true, "verified": true, "source": "journald", "sources": []SSHSource{{IP: "198.51.100.7", Failed: 40}}}, nil
	}
	textLogins = func(*Env, string) (int, []string, []string) { return 0, nil, nil }
	for _, c := range []struct {
		name string
		n    int
		err  error
		ok   bool
	}{
		{"sshd wrote them", 3, nil, true},
		{"another program in sshd's unit wrote them", 0, nil, false},
		{"journald could not tell", 0, errors.New("marker"), false},
	} {
		sshdJournal = func(context.Context, time.Time, string) (int, error) { return c.n, c.err }
		if err := loginGate(context.Background(), &Env{}, ip, false); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

// P5 part 3: block_ip's attack gate. A block of an address attack
// detection saw needs a verified L2 or L3 group of its own; unverified,
// overflow, L1 and Unknown groups never give one (override only for
// unverified, and only from the server).

func gateState(t *testing.T, gs ...*detect.Group) {
	t.Helper()
	old := attackState
	t.Cleanup(func() { attackState = old })
	a := &detect.Attacks{Version: 1, Groups: map[string]*detect.Group{}, Overflow: map[string]*detect.Group{}}
	for _, g := range gs {
		if g.Prefix == detect.PrefixOverflow {
			a.Overflow[g.Key] = g
		} else {
			a.Groups[g.Key] = g
		}
	}
	attackState = func() (*detect.Attacks, error) { return a, nil }
}

func grp(key, prefix, level string, verified bool, ips ...string) *detect.Group {
	return &detect.Group{Key: key, Prefix: prefix, Entry: "code:marker:a.php:1", Level: level, Unverified: !verified, IPs: ips,
		Reasons: []string{"marker reason"}, Last: time.Now()}
}

func TestBlockIPAttackGate(t *testing.T) {
	ip := net.ParseIP("198.51.100.7")
	for _, c := range []struct {
		name            string
		groups          []*detect.Group
		override        bool
		applies, refuse bool
		say             string
	}{ // applies: the attempts speak for the address (gateAllow or gateRefuse)
		{"no attempts: not this gate's", nil, false, false, false, ""},
		{"another address only", []*detect.Group{grp("a", "198.51.100.0/24", "L2", true, "198.51.100.8")}, false, false, false, ""},
		{"verified L2 of its own", []*detect.Group{grp("a", "198.51.100.0/24", "L2", true, "198.51.100.7")}, false, true, false, ""},
		{"verified L3 of its own", []*detect.Group{grp("a", "198.51.100.0/24", "L3", true, "198.51.100.7")}, false, true, false, ""},
		{"unverified L2", []*detect.Group{grp("a", "198.51.100.0/24", "L2", false, "198.51.100.7")}, false, true, true, "shentu chat"},
		{"unverified L2, override (server): its logins decide", []*detect.Group{grp("a", "198.51.100.0/24", "L2", false, "198.51.100.7")}, true, false, false, ""},
		{"overflow only", []*detect.Group{grp("o", detect.PrefixOverflow, "L3", true, "198.51.100.7")}, false, true, true, "overflow"},
		{"overflow only, override", []*detect.Group{grp("o", detect.PrefixOverflow, "L3", true, "198.51.100.7")}, true, true, true, "overflow"},
		{"L1 only", []*detect.Group{grp("a", "198.51.100.0/24", "L1", true, "198.51.100.7")}, false, true, true, "not enough"},
		{"L1 only, override (server): its logins decide", []*detect.Group{grp("a", "198.51.100.0/24", "L1", true, "198.51.100.7")}, true, false, false, ""},
		{"unknown only", []*detect.Group{grp("a", "*", "unknown", true, "198.51.100.7")}, false, true, true, "not enough"},
		{"overflow and a verified L2", []*detect.Group{grp("o", detect.PrefixOverflow, "L3", true, "198.51.100.7"), grp("a", "198.51.100.0/24", "L2", true, "198.51.100.7")}, false, true, false, ""},
	} {
		gateState(t, c.groups...)
		v, err := attackGate(ip, c.override)
		applies := v != gateNone
		if applies != c.applies || (err != nil) != c.refuse || err != nil && !strings.Contains(err.Error(), c.say) {
			t.Errorf("%s: applies %v, err %v", c.name, applies, err)
		}
	}
	// A state that cannot be read refuses (whether the attempts can be
	// believed is unknown), not falls back to the login gate.
	old := attackState
	t.Cleanup(func() { attackState = old })
	attackState = func() (*detect.Attacks, error) { return nil, errors.New("marker") }
	if v, err := attackGate(ip, false); v != gateRefuse || err == nil {
		t.Errorf("unreadable state: %v %v", v, err)
	}
}

// Security review of part 3: attempts that do not justify a block do not
// shield an address its verified SSH logins condemn; unverified or no SSH
// evidence still refuses.
func TestBlockGateFallsBackToVerifiedLogins(t *testing.T) {
	ip := net.ParseIP("198.51.100.7")
	oldS, oldT := loginSummary, textLogins
	t.Cleanup(func() { loginSummary, textLogins = oldS, oldT })
	summary := func(verified bool) func(context.Context, *Env, time.Time, string) (map[string]any, error) {
		return func(context.Context, *Env, time.Time, string) (map[string]any, error) {
			return map[string]any{"complete": true, "verified": verified, "source": "journald",
				"sources": []SSHSource{{IP: "198.51.100.7", Failed: 40}}}, nil
		}
	}
	textLogins = func(*Env, string) (int, []string, []string) { return 0, nil, nil }
	for _, c := range []struct {
		name     string
		group    *detect.Group
		verified bool
		ok       bool
	}{
		{"one L1 request, verified SSH logins", grp("a", "198.51.100.0/24", "L1", true, "198.51.100.7"), true, true},
		{"overflow only, verified SSH logins", grp("o", detect.PrefixOverflow, "L3", true, "198.51.100.7"), true, true},
		{"unverified L2, verified SSH logins", grp("a", "198.51.100.0/24", "L2", false, "198.51.100.7"), true, true},
		{"one L1 request, unverified SSH logins", grp("a", "198.51.100.0/24", "L1", true, "198.51.100.7"), false, false},
	} {
		gateState(t, c.group)
		loginSummary = summary(c.verified)
		if err := blockGate(context.Background(), &Env{}, ip, false); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// No SSH events at all: the weak attempts' refusal stands.
	gateState(t, grp("a", "198.51.100.0/24", "L1", true, "198.51.100.7"))
	loginSummary = func(context.Context, *Env, time.Time, string) (map[string]any, error) {
		return map[string]any{"complete": true, "verified": true, "source": "journald"}, nil
	}
	if err := blockGate(context.Background(), &Env{}, ip, false); err == nil || !strings.Contains(err.Error(), "not enough") {
		t.Errorf("no logins, L1 only: %v", err)
	}
}

// From a chat channel, override_unverified is refused before the gate:
// an unverified group cannot be blocked from Telegram, at any level.
func TestBlockIPAttackGateRemote(t *testing.T) {
	gateState(t, grp("a", "198.51.100.0/24", "L2", false, "198.51.100.7"))
	args, _ := json.Marshal(map[string]any{"ip": "198.51.100.7", "reason": "marker", "override_unverified": true})
	if _, err := blockIP.Run(context.Background(), &Env{Remote: true}, args); err == nil || !strings.Contains(err.Error(), "chat channel") {
		t.Errorf("override from Telegram: %v", err)
	}
	args, _ = json.Marshal(map[string]any{"ip": "198.51.100.7", "reason": "marker"})
	if _, err := blockIP.Run(context.Background(), &Env{Remote: true}, args); err == nil || !strings.Contains(err.Error(), "cannot be believed") {
		t.Errorf("unverified from Telegram: %v", err)
	}
}

func TestAttackAttempts(t *testing.T) {
	g := grp("a", "198.51.100.0/24", "L2", true, "198.51.100.7")
	g.Severity, g.Count, g.Samples = "high", 3, []string{"GET /m\nx"}
	old := grp("b", "192.0.2.0/24", "L2", true, "192.0.2.1")
	old.Last = time.Now().Add(-48 * time.Hour)
	gateState(t, g, old)
	out, err := attackAttempts.Run(context.Background(), &Env{}, json.RawMessage(`{"hours":24}`))
	if err != nil {
		t.Fatal(err)
	}
	list := out.(map[string]any)["groups"].([]map[string]any)
	if len(list) != 1 || list[0]["count"] != 3 || list[0]["verified"] != true || strings.Contains(list[0]["samples"].([]string)[0], "\n") {
		t.Errorf("%+v", list)
	}
	if attackAttempts.Control {
		t.Error("attack_attempts is read only")
	}
	if out.(map[string]any)["untrusted"] == nil {
		t.Error("no untrusted label")
	}
	// Security review of part 3: no samples to a chat channel's model.
	out, _ = attackAttempts.Run(context.Background(), &Env{Remote: true}, json.RawMessage(`{}`))
	if _, ok := out.(map[string]any)["groups"].([]map[string]any)[0]["samples"]; ok {
		t.Error("samples given to a chat channel's model")
	}
}

// Review 1 of #91: an IPv4-mapped address is the address (B-1); an
// operator overriding on the server is not stopped by forgeable weak or
// unverified groups (S-1); an internal address needs an override (S-5).
func TestBlockGateReview1(t *testing.T) {
	gateState(t, grp("a", "198.51.100.0/24", "L2", false, "::ffff:198.51.100.7"))
	for _, q := range []string{"198.51.100.7", "::ffff:198.51.100.7"} {
		if v, err := attackGate(net.ParseIP(q), false); v != gateRefuse || err == nil {
			t.Errorf("mapped unverified group asked as %s: %v %v", q, v, err)
		}
	}
	oldS, oldT := loginSummary, textLogins
	t.Cleanup(func() { loginSummary, textLogins = oldS, oldT })
	loginSummary = func(context.Context, *Env, time.Time, string) (map[string]any, error) {
		return map[string]any{"complete": true, "verified": true, "source": "journald"}, nil
	}
	textLogins = func(*Env, string) (int, []string, []string) { return 0, nil, nil }
	gateState(t, grp("a", "198.51.100.0/24", "unknown", false, "198.51.100.7"))
	if err := blockGate(context.Background(), &Env{}, net.ParseIP("198.51.100.7"), true); err != nil {
		t.Errorf("override on the server, forged unknown group: %v", err)
	}
	gateState(t)
	for _, q := range []string{"10.1.2.3", "192.168.1.5", "172.16.0.9", "100.64.3.4", "169.254.1.1", "fd00::1", "::ffff:10.0.0.1"} {
		if err := blockGate(context.Background(), &Env{}, net.ParseIP(q), false); err == nil || !strings.Contains(err.Error(), "load balancer") {
			t.Errorf("%s: %v", q, err)
		}
		if err := blockGate(context.Background(), &Env{}, net.ParseIP(q), true); err != nil {
			t.Errorf("%s with override: %v", q, err)
		}
	}
}
