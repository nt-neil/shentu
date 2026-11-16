package detect

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// P5 part 6: the small deferred items. Neutral markers only.

// n18-2, n19-2, n18-3/n21: Spring's {*path}, Laravel's optional {id?},
// a colon inside a segment is a literal.
func TestRouteFormsP5(t *testing.T) {
	for pattern, c := range map[string]struct{ yes, no []string }{
		"/files/{*path}":       {[]string{"/files/a/b/c"}, []string{"/other/a"}},
		"/users/{id?}":         {[]string{"/users", "/users/5"}, []string{"/users/5/6"}},
		"/v1/items:batch":      {[]string{"/v1/items:batch", "/api/v1/items:batch"}, []string{"/v1/items:other", "/v1/items"}},
		"/v1/:name/items:sync": {[]string{"/v1/x/items:sync"}, []string{"/v1/x/items:other"}},
		// Security review: after a delimiter a colon is still a parameter.
		"/flights/:from-:to": {[]string{"/flights/a-b"}, []string{"/flights/a"}},
		"/file.:ext":         {[]string{"/file.txt"}, []string{"/file."}},
	} {
		re, _ := routeRegexp(pattern)
		if re == nil {
			t.Errorf("%s: no expression", pattern)
			continue
		}
		for _, p := range c.yes {
			if !re.MatchString(p) {
				t.Errorf("%s should match %q (%s)", pattern, p, re)
			}
		}
		for _, p := range c.no {
			if re.MatchString(p) {
				t.Errorf("%s should not match %q (%s)", pattern, p, re)
			}
		}
	}
}

// n24-3: sources that are not addresses share one group past
// MaxNonIPPrefixes; n24-5: a group keeps its latest samples.
func TestNonIPAndSamples(t *testing.T) {
	a := newAttacks()
	for i := 0; i < MaxNonIPPrefixes+5; i++ {
		a.Add(att(fmt.Sprintf("marker-host-%d", i), "e1", LevelPayload, t0), t0)
	}
	n := 0
	for _, g := range a.Groups {
		if g.Prefix == PrefixNonIP {
			n += g.Count
		}
	}
	if len(a.Groups) != MaxNonIPPrefixes+1 || n != 5 {
		t.Errorf("%d groups, %d in %s", len(a.Groups), n, PrefixNonIP)
	}
	b := newAttacks()
	var g *Group
	for i := 0; i < 5; i++ {
		x := att("192.0.2.1", "e1", LevelPayload, t0)
		x.Sample = fmt.Sprintf("GET /marker/%d", i)
		g = b.Add(x, t0)
	}
	if strings.Join(g.Samples, ",") != "GET /marker/2,GET /marker/3,GET /marker/4" {
		t.Errorf("samples %v, want the latest three", g.Samples)
	}
}

// p5-review2, p56-review3: escape=json keeps a raw byte as it is whether
// or not the value holds an escape.
func TestUnescapeJSONRawBytes(t *testing.T) {
	for in, want := range map[string]string{
		"a\xffb":        "a\xffb",
		`a\"b` + "\xff": "a\"b\xff",
		`é😀`:            "é😀",
		`a\/b\tc`:       "a/b\tc",
	} {
		got, ok := unescapeJSON(in)
		if !ok || got != want {
			t.Errorf("unescapeJSON(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{`a\q`, `a\`, `\u12`} {
		if _, ok := unescapeJSON(bad); ok {
			t.Errorf("%q taken", bad)
		}
	}
}

var _ = time.Second

// p56-review3: a directory not synced after the rename is said as saved
// but not synced, not as not saved.
func TestDirNotSynced(t *testing.T) {
	err := dirSynced(t.TempDir() + "/marker-missing")
	if !errors.Is(err, ErrDirNotSynced) && err != nil {
		t.Errorf("%v", err)
	}
}

// Review 1 of #91 (B-1): a dual-stack listener's ::ffff:<IPv4> is stored
// as the IPv4 address; GroupsOf finds it in either form.
func TestMappedClient(t *testing.T) {
	p, err := NginxParser(`$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`, "")
	if err != nil {
		t.Fatal(err)
	}
	r, ok := p.Parse([]byte(`::ffff:203.0.113.5 - - [16/Nov/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "marker"`))
	if !ok || r.Client != "203.0.113.5" {
		t.Errorf("client %q", r.Client)
	}
	a := newAttacks()
	a.Add(att("::ffff:198.51.100.7", "e1", LevelPayload, t0), t0)
	if len(a.GroupsOf("198.51.100.7")) != 1 || len(a.GroupsOf("::ffff:198.51.100.7")) != 1 {
		t.Error("a mapped address not found as its IPv4 one")
	}
}

// Review 1 of #91 (N-1): L1 is never pending: past the TTL it is not
// counted as dropped, and a flood of L1 groups does not push out a
// notified L2 one.
func TestL1NeverPending(t *testing.T) {
	a := newAttacks()
	a.Add(att("192.0.2.1", "e1", LevelRoute, t0), t0)
	a.prune(t0.Add(AttackTTL + time.Hour))
	if a.DroppedPending != 0 || len(a.Overflow) != 0 {
		t.Errorf("an L1 group past the TTL: dropped %d, overflow %d", a.DroppedPending, len(a.Overflow))
	}
	b := newAttacks()
	g := b.Add(att("203.0.113.1", "target", LevelPayload, t0), t0)
	b.Notified(g, t0)
	for i := 0; i < MaxGroups+10; i++ {
		b.Add(att(fmt.Sprintf("10.%d.%d.1", i/256, i%256), "e", LevelRoute, t0.Add(time.Duration(i+1)*time.Second)), t0)
	}
	b.prune(t0.Add(time.Hour))
	if len(b.GroupsOf("203.0.113.1")) != 1 || b.DroppedPending != 0 {
		t.Errorf("the notified L2 group pushed out by L1 ones (dropped %d)", b.DroppedPending)
	}
}
