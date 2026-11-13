package hostenv

import (
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
