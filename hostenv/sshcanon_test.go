package hostenv

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// One source however a line writes its address: an IPv4-mapped address and
// upper-case IPv6 count with the plain form, and onlyIP matches them.
func TestSSHLoginsCanonicalIP(t *testing.T) {
	now := time.Now()
	line := func(ip string) string {
		return now.Add(-time.Minute).UTC().Format(time.RFC3339) + " vm sshd[1]: Failed password for root from " + ip + " port 22 ssh2"
	}
	c := NewSSHLogins(now.Add(-time.Hour), now, "203.0.113.77")
	for _, ip := range []string{"203.0.113.77", "::ffff:203.0.113.77", "::FFFF:203.0.113.77"} {
		c.Add(line(ip))
	}
	s, _ := MaxLogins(c)
	if len(s) != 1 || s[0].IP != "203.0.113.77" || s[0].Failed != 3 {
		t.Errorf("%+v", s)
	}
	c = NewSSHLogins(now.Add(-time.Hour), now, "::ffff:203.0.113.77")
	c.Add(line("203.0.113.77"))
	c.Add(line("2001:DB8::1"))
	c6 := NewSSHLogins(now.Add(-time.Hour), now, "2001:db8::1")
	c6.Add(line("2001:DB8::1"))
	if s, _ := MaxLogins(c); len(s) != 1 || s[0].Failed != 1 {
		t.Errorf("mapped onlyIP: %+v", s)
	}
	if s, _ := MaxLogins(c6); len(s) != 1 || s[0].IP != "2001:db8::1" {
		t.Errorf("upper-case IPv6: %+v", s)
	}
}

// The text auth logs are read even when journald has sshd entries, so a
// forged line there is seen by block_ip's gate.
func TestScanTextAuthLogsBesideJournald(t *testing.T) {
	now := time.Now()
	forged := now.Add(-time.Hour).UTC().Format(time.RFC3339) + " vm sshd[1]: Failed password for root from 203.0.113.77 port 22 ssh2"
	real := now.Add(-time.Hour).UTC().Format(time.RFC3339) + " vm sshd[2]: Failed password for root from 198.51.100.4 port 22 ssh2"
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "auth.log"), []byte(forged+"\n"), 0o600)
	src := &journalToo{Live: &Live{Remap: map[string]string{"/var/log": dir}}, lines: []string{real}}
	logs := []string{"/var/log/auth.log"}
	since := now.Add(-24 * time.Hour)
	source, verified, _ := LinuxCollector{}.ScanAuthLogs(context.Background(), src, logs, since, func() func(string) { return func(string) {} })
	if source != "journald" || !verified {
		t.Fatalf("journald not taken: %q %v", source, verified)
	}
	c := NewSSHLogins(since, now, "203.0.113.77")
	read := LinuxCollector{}.ScanTextAuthLogs(src, logs, since, c.Add)
	if s, _ := MaxLogins(c); len(read) != 1 || len(s) != 1 || s[0].Failed != 1 {
		t.Errorf("read %v, %+v", read, s)
	}
}
