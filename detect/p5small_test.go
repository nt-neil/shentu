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
