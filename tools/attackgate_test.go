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
	}{
		{"no attempts: not this gate's", nil, false, false, false, ""},
		{"another address only", []*detect.Group{grp("a", "198.51.100.0/24", "L2", true, "198.51.100.8")}, false, false, false, ""},
		{"verified L2 of its own", []*detect.Group{grp("a", "198.51.100.0/24", "L2", true, "198.51.100.7")}, false, true, false, ""},
		{"verified L3 of its own", []*detect.Group{grp("a", "198.51.100.0/24", "L3", true, "198.51.100.7")}, false, true, false, ""},
		{"unverified L2", []*detect.Group{grp("a", "198.51.100.0/24", "L2", false, "198.51.100.7")}, false, true, true, "shentu chat"},
		{"unverified L2, override (server)", []*detect.Group{grp("a", "198.51.100.0/24", "L2", false, "198.51.100.7")}, true, true, false, ""},
		{"overflow only", []*detect.Group{grp("o", detect.PrefixOverflow, "L3", true, "198.51.100.7")}, false, true, true, "overflow"},
		{"overflow only, override", []*detect.Group{grp("o", detect.PrefixOverflow, "L3", true, "198.51.100.7")}, true, true, true, "overflow"},
		{"L1 only", []*detect.Group{grp("a", "198.51.100.0/24", "L1", true, "198.51.100.7")}, true, true, true, "not enough"},
		{"unknown only", []*detect.Group{grp("a", "*", "unknown", true, "198.51.100.7")}, false, true, true, "not enough"},
		{"overflow and a verified L2", []*detect.Group{grp("o", detect.PrefixOverflow, "L3", true, "198.51.100.7"), grp("a", "198.51.100.0/24", "L2", true, "198.51.100.7")}, false, true, false, ""},
	} {
		gateState(t, c.groups...)
		applies, err := attackGate(ip, c.override)
		if applies != c.applies || (err != nil) != c.refuse || err != nil && !strings.Contains(err.Error(), c.say) {
			t.Errorf("%s: applies %v, err %v", c.name, applies, err)
		}
	}
	// A state that cannot be read refuses (whether the attempts can be
	// believed is unknown), not falls back to the login gate.
	old := attackState
	t.Cleanup(func() { attackState = old })
	attackState = func() (*detect.Attacks, error) { return nil, errors.New("marker") }
	if applies, err := attackGate(ip, false); !applies || err == nil {
		t.Errorf("unreadable state: %v %v", applies, err)
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
}
