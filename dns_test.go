package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
)

// Shentu's binary asks Go's resolver for no EDNS(0) record (main.go's
// go:debug line): VMware's NAT DNS put the OPT record in place of the last
// answer, so with it every lookup said "no such host".
func TestNoEDNS0Directive(t *testing.T) {
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	at, pkg := strings.Index(src, "//go:debug netedns0=0\n"), strings.Index(src, "\npackage main")
	if at < 0 || pkg < 0 || at > pkg {
		t.Error("main.go has no //go:debug netedns0=0 before its package clause")
	}
}

// A failed name lookup in the vulnerability check says it is this host's DNS.
func TestUncheckedVulnsDNSHint(t *testing.T) {
	err := fmt.Errorf("osv: %w", &net.DNSError{Err: "no such host", Name: "api.osv.dev", Server: "192.168.22.2:53", IsNotFound: true})
	got := uncheckedVulns("installed packages", nil, err)
	if !strings.Contains(got, "check this host's DNS") || !strings.Contains(got, "getent hosts api.osv.dev") {
		t.Errorf("%q", got)
	}
	if got := uncheckedVulns("installed packages", nil, errors.New("osv: 503")); strings.Contains(got, "DNS") {
		t.Errorf("hint on a non-DNS error: %q", got)
	}
}
