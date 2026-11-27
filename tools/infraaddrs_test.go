package tools

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// infraAddrs reads the host source's resolv.conf and routes (host-source
// PR-2a): a replay or another host's survey is never answered by the
// machine running it. Made-up addresses (192.0.2.0/24, 2001:db8::/32).
func TestInfraAddrsHostSource(t *testing.T) {
	h := memHost{
		"/etc/resolv.conf":                 "# made up\nnameserver 192.0.2.53\nsearch example.test\n",
		"/run/systemd/resolve/resolv.conf": "nameserver 2001:db8::53\n",
		"/proc/net/route": "Iface\tDestination\tGateway\tFlags\n" +
			"eth0\t00000000\t010200C0\t0003\n" + // default via 192.0.2.1, little-endian
			"eth0\t000200C0\t00000000\t0001\n", // the subnet itself: no gateway
		"/proc/net/ipv6_route": "00000000000000000000000000000000 00 00000000000000000000000000000000 00 20010db8000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n",
	}
	m, err := infraAddrs(h)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"192.0.2.53", "2001:db8::53", "192.0.2.1", "2001:db8::1"} {
		if !m[ip] {
			t.Errorf("%s not found: %v", ip, m)
		}
	}
	if len(m) != 4 {
		t.Errorf("infra %v, want the 4 above only", m)
	}
	// Nothing on the host source: nothing found, though the machine running
	// the test has its own resolv.conf (read locally before).
	if m, err := infraAddrs(memHost{}); err != nil || len(m) != 0 {
		t.Errorf("an empty host: %v %v, want nothing (the machine's own files never read)", m, err)
	}
}

// deniedHost fails one path with a permission error, as an unreadable file.
type deniedHost struct {
	memHost
	denied string
}

func (h deniedHost) ReadFile(p string) ([]byte, error) {
	if p == h.denied {
		return nil, &os.PathError{Op: "open", Path: p, Err: os.ErrPermission}
	}
	return h.memHost.ReadFile(p)
}

// A routing table or resolv.conf there but not read refuses the block: the
// list is not taken for empty (before, the error was dropped and the
// gateway could be blocked).
func TestInfraAddrsUnreadRefuses(t *testing.T) {
	for _, f := range []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf", "/proc/net/route", "/proc/net/ipv6_route"} {
		h := deniedHost{memHost{"/etc/resolv.conf": "nameserver 192.0.2.53\n"}, f}
		if _, err := infraAddrs(h); err == nil || err.Error() != f+" could not be read (permission denied)" {
			t.Errorf("%s unread: %v", f, err)
		}
		withHost(t, h)
		args, _ := json.Marshal(map[string]string{"ip": "198.51.100.7"})
		if _, _, _, err := checkBlock(args); codeOf(err) != BlockStateError || !strings.Contains(err.Error(), "gateway or DNS") {
			t.Errorf("%s unread: block %v (code %v), want refused as state_error", f, err, codeOf(err))
		}
	}
}
