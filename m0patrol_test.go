package main

import (
	"errors"
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
