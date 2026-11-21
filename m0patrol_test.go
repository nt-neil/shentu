package main

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/nt-neil/shentu/tools"
)

// N-177-2: an empty saved baseline ({} from a release that read no port on
// macOS) is a first one: the first good read warns of no port, the next
// warns of a new one.
func TestPortBaselineEmptyIsFirst(t *testing.T) {
	st := &state{Ports: map[string]bool{}}
	ports := []tools.Port{{Proto: "tcp", Addr: "0.0.0.0", Port: 22, Process: "launchd"}, {Proto: "udp", Addr: "0.0.0.0", Port: 5353, Process: "mDNSResponder"}}
	if f := portFindings(st, ports); len(f) != 0 {
		t.Errorf("first good read after {}: %v", f)
	}
	ports = append(ports, tools.Port{Proto: "tcp", Addr: "127.0.0.1", Port: 7777, Process: "exampledb"})
	if f := portFindings(st, ports); len(f) != 1 || f[0].Key != "port:tcp:7777" {
		t.Errorf("a new port: %v", f)
	}
}

// S-177-1: a process list that cannot be read is "not checked", not "no
// suspicious process".
func TestProcFindingsNotChecked(t *testing.T) {
	f, why := procFindings(nil, errors.New("ps failed"))
	if len(f) != 0 || !strings.Contains(why, "Not checked: processes") {
		t.Errorf("findings %v, why %q", f, why)
	}
	if _, why := procFindings([]tools.Proc{}, nil); why != "" {
		t.Errorf("read, nothing found: %q", why)
	}
}

// The automated review's point on N-177-2: once a read made the baseline,
// an empty one is a host with no listening port, and the first port opened
// on it is new (the empty-is-first migration happens once, for a state
// from before PortsV).
func TestPortBaselineEmptyAfterRead(t *testing.T) {
	st := &state{}
	if f := portFindings(st, nil); len(f) != 0 || st.PortsV != portsBaselineV {
		t.Fatalf("first read of no port: %v, v %d", f, st.PortsV)
	}
	if f := portFindings(st, []tools.Port{{Proto: "tcp", Addr: "0.0.0.0", Port: 4444, Process: "nc"}}); len(f) != 1 {
		t.Errorf("a port opened on a host with none: %v", f)
	}
	old := &state{Ports: map[string]bool{"tcp:22": true}} // a Linux state from before PortsV
	if f := portFindings(old, []tools.Port{{Proto: "tcp", Port: 22}, {Proto: "tcp", Port: 8080}}); len(f) != 1 {
		t.Errorf("an old, non-empty baseline: %v", f)
	}
}

// N-180-1: accounts or authorized_keys that could not be read are in the
// patrol's "not checked"; sudoers alone (no root) is not a patrol check.
func TestAccountsUnchecked(t *testing.T) {
	got := accountsUnchecked(tools.Accounts{NotRead: []string{"accounts", "authorized_keys", "sudoers"}, Note: "dscl failed"})
	if !strings.Contains(got, "Not checked: accounts") || !strings.Contains(got, "Not checked: authorized_keys") {
		t.Errorf("unchecked: %q", got)
	}
	if got := accountsUnchecked(tools.Accounts{NotRead: []string{"sudoers"}}); got != "" {
		t.Errorf("sudoers only: %q", got)
	}
}

// M0: on macOS the default watched paths are macOS's own (/etc is
// /private/etc; Homebrew; launchd jobs).
func TestMacDefaultWatchPaths(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}
	p := filepath.Join(t.TempDir(), "shentu.toml")
	os.WriteFile(p, []byte("state_dir = "+strconv.Quote(t.TempDir())+"\n"), 0o600)
	cfg, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"/private/etc", "/opt/homebrew/bin", "/Library/LaunchDaemons"} {
		if !slices.Contains(cfg.Tools.WatchPaths, w) {
			t.Errorf("watch paths %v lack %s", cfg.Tools.WatchPaths, w)
		}
	}
}
