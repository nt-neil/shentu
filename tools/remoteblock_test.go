package tools

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/detect"
)

// v0.5.1 B: RemoteBlockCheck decides as block_ip from Telegram decides,
// and names the refusal with a fixed word (n3 B1-B4).
func TestRemoteBlockCheckCodes(t *testing.T) {
	past := grp("p", "203.0.113.0/24", "L2", false, "203.0.113.200") // its addresses past the listed one may hold .12
	past.IPsSeen = 9
	for _, c := range []struct {
		name   string
		groups []*detect.Group
		ip     string
		logins int
		want   BlockCode
	}{
		{"verified L2 listing it", []*detect.Group{grp("a", "203.0.113.0/24", "L2", true, "203.0.113.12")}, "203.0.113.12", 0, BlockOK},
		{"verified L3 listing it", []*detect.Group{grp("a", "203.0.113.0/24", "L3", true, "203.0.113.12")}, "203.0.113.12", 0, BlockOK},
		{"sshd's own logins", nil, "203.0.113.12", 40, BlockOK},
		{"B1 unverified L3", []*detect.Group{grp("a", "203.0.113.0/24", "L3", false, "203.0.113.12")}, "203.0.113.12", 0, BlockUnverified},
		{"B1 unverified L2", []*detect.Group{grp("a", "203.0.113.0/24", "L2", false, "203.0.113.12")}, "203.0.113.12", 0, BlockUnverified},
		{"B2 overflow summary", []*detect.Group{grp("o", detect.PrefixOverflow, "L3", true, "203.0.113.12")}, "203.0.113.12", 0, BlockOverflow},
		{"B2 past a group's listed addresses", []*detect.Group{past}, "203.0.113.12", 0, BlockUnverified},
		{"L1 only", []*detect.Group{grp("a", "203.0.113.0/24", "L1", true, "203.0.113.12")}, "203.0.113.12", 0, BlockWeak},
		{"B4 logged with a port", []*detect.Group{grp("a", "203.0.113.12:51234", "L2", true, "203.0.113.12:51234")}, "203.0.113.12", 0, BlockWeak},
		{"no evidence", nil, "203.0.113.12", 0, BlockNoEvidence},
		{"B3 private", []*detect.Group{grp("a", "10.0.0.0/24", "L3", true, "10.0.0.1")}, "10.0.0.1", 0, BlockInternal},
		{"B3 CGNAT", []*detect.Group{grp("a", "100.64.0.0/24", "L3", true, "100.64.0.9")}, "100.64.0.9", 0, BlockInternal},
		{"B3 loopback", []*detect.Group{grp("a", "127.0.0.0/24", "L3", true, "127.0.0.1")}, "127.0.0.1", 0, BlockInternal},
		{"B3 unique local", []*detect.Group{grp("a", "fd00::/64", "L3", true, "fd00::1")}, "fd00::1", 0, BlockInternal},
		{"B4 NAT64 of a private address", []*detect.Group{grp("a", "64:ff9b::/96", "L3", true, "64:ff9b::a00:1")}, "64:ff9b::a00:1", 0, BlockInternal},
		{"B4 NAT64 of a public address listed as IPv4", []*detect.Group{grp("a", "203.0.113.0/24", "L3", true, "203.0.113.12")}, "64:ff9b::cb00:710c", 0, BlockWeak},
	} {
		gateState(t, c.groups...)
		remoteLogins(t, c.ip, c.logins)
		preview, code, err := RemoteBlockCheck(context.Background(), &Env{}, net.ParseIP(c.ip))
		if code != c.want {
			t.Errorf("%s: code %q, want %q (%v)", c.name, code, c.want, err)
		}
		if (err == nil) != (code == BlockOK) {
			t.Errorf("%s: code %q with error %v", c.name, code, err)
		}
		if code == BlockOK && !strings.Contains(preview, "nft add element") {
			t.Errorf("%s: preview %q", c.name, preview)
		}
		// The decision is block_ip's own from Telegram.
		gerr := blockGate(context.Background(), &Env{Remote: true}, net.ParseIP(c.ip), false)
		if _, _, _, cerr := checkBlock(ProposalBlockArgs(net.ParseIP(c.ip))); cerr != nil {
			gerr = cerr
		}
		if (gerr == nil) != (code == BlockOK) {
			t.Errorf("%s: RemoteBlockCheck says %q, block_ip's gate %v", c.name, code, gerr)
		}
	}
}

// The state not readable is state_error; an error with no code is never ok.
func TestRemoteBlockCheckStateError(t *testing.T) {
	old := attackState
	t.Cleanup(func() { attackState = old })
	attackState = func() (*detect.Attacks, error) { return nil, errors.New("bad state") }
	remoteLogins(t, "203.0.113.12", 0)
	if _, code, _ := RemoteBlockCheck(context.Background(), &Env{}, net.ParseIP("203.0.113.12")); code != BlockStateError {
		t.Errorf("unreadable state: %q", code)
	}
	if codeOf(errors.New("x")) != BlockStateError || codeOf(nil) != BlockOK {
		t.Error("codeOf does not fail closed")
	}
	if _, code, _ := RemoteBlockCheck(context.Background(), &Env{}, nil); code != BlockNotCanonical {
		t.Errorf("nil address: %q", code)
	}
}

// RemoteBlockCheck runs as Telegram whatever env it is given, and never
// takes an override.
func TestRemoteBlockCheckAlwaysRemote(t *testing.T) {
	gateState(t) // no evidence: the server's own gate lets it through, Telegram's does not
	remoteLogins(t, "203.0.113.12", 0)
	env := &Env{} // the server's own terminal
	if blockGate(context.Background(), env, net.ParseIP("203.0.113.12"), false) != nil {
		t.Fatal("the server's gate refuses an address with no evidence: this test no longer tells the two apart")
	}
	if _, code, _ := RemoteBlockCheck(context.Background(), env, net.ParseIP("203.0.113.12")); code != BlockNoEvidence {
		t.Errorf("server env: %q", code)
	}
	if env.Remote {
		t.Error("the caller's env was changed")
	}
	var a ipArgs
	if json.Unmarshal(ProposalBlockArgs(net.ParseIP("203.0.113.12")), &a) != nil || a.OverrideUnverified || a.IP != "203.0.113.12" {
		t.Error("the proposal's arguments carry an override")
	}
}
