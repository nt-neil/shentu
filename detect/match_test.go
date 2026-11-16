package detect

import (
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/nt-neil/shentu/detect/sig"
)

func loadSigs(t *testing.T, src string) []sig.Signature {
	t.Helper()
	ss, err := sig.LoadFS(fstest.MapFS{"s/a.toml": {Data: []byte(src)}}, "s")
	if err != nil {
		t.Fatal(err)
	}
	return ss
}

// The normalization the commander listed, each case.
func TestNormalize(t *testing.T) {
	cases := []struct {
		name  string
		query string
		path  string
		check func(q Request) bool
	}{
		{"case", "ID=1%20UNION%20Select", "/", func(q Request) bool { return q.Params["id"][0] == "1 union select" }},
		{"plus and %20", "q=a+b%20c", "/", func(q Request) bool { return q.Params["q"][0] == "a b c" }},
		{"%u (IIS)", "q=%u0027%u003b", "/", func(q Request) bool { return q.Params["q"][0] == "';" && q.Encoded }},
		{"repeated parameter", "id=1&id=2%27", "/", func(q Request) bool { return len(q.Params["id"]) == 2 && q.Params["id"][1] == "2'" }},
		{"null byte", "f=a.php%00.jpg", "/", func(q Request) bool { return q.Params["f"][0] == "a.php\x00.jpg" }},
		{"overlong utf-8", "", "/a/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", func(q Request) bool {
			return strings.Contains(q.RawPath, "../../etc/passwd") && q.Encoded
		}},
		{"double encoding", "f=%252e%252e%252f", "/", func(q Request) bool { return q.Params["f"][0] == "../" && q.Encoded }},
		{"triple encoding stops at two rounds", "f=%25252e", "/", func(q Request) bool { return q.Params["f"][0] == "%2e" }},
		{"dot segments kept raw, resolved for routes", "", "/static/../../etc/passwd", func(q Request) bool {
			return q.RawPath == "/static/../../etc/passwd" && q.Path == "/etc/passwd"
		}},
		{"malformed escape kept", "q=%zz%2", "/", func(q Request) bool { return q.Params["q"][0] == "%zz%2" }},
	}
	for _, c := range cases {
		q := Normalize(AccessRecord{Method: "get", Path: c.path, Query: c.query})
		if !c.check(q) {
			t.Errorf("%s: %+v", c.name, q)
		}
	}
	long := Normalize(AccessRecord{Path: "/", Query: "q=" + strings.Repeat("a", MaxNormalized+10)})
	if !long.Cut {
		t.Error("a value past MaxNormalized not cut")
	}
	var many []string
	for i := 0; i < MaxParams+5; i++ {
		many = append(many, "p=1")
	}
	if !Normalize(AccessRecord{Path: "/", Query: strings.Join(many, "&")}).Cut {
		t.Error("parameters past MaxParams not said cut")
	}
}

const matchSigs = `
[[signature]]
id = "sqli-union"
title = "union"
class = "sqli"
source = "shentu"
license = "Apache-2.0"
[[signature.match]]
part = "any_param"
regex = '\bunion\b\s+select\b'

[[signature]]
id = "wp-ajax-x"
title = "route and param"
class = "sqli"
source = "shentu"
license = "Apache-2.0"
[[signature.route]]
methods = ["post", "GET"]
path = "/wp-admin/admin-ajax.php"
[[signature.match]]
part = "param"
param = "action"
contains = ["evil_action"]
[[signature.match]]
part = "param"
param = "id"
regex = "'"

[[signature]]
id = "route-only"
title = "a route alone"
class = "path"
source = "shentu"
license = "Apache-2.0"
[[signature.route]]
path = "/.env"
`

func TestMatch(t *testing.T) {
	m := NewMatcher(loadSigs(t, matchSigs))
	ids := func(rs []MatchResult) string {
		var out []string
		for _, r := range rs {
			for _, h := range r.Hits {
				out = append(out, h.Signature)
			}
		}
		return strings.Join(out, ",")
	}
	if got := ids(m.MatchRecord(AccessRecord{Method: "GET", Path: "/x", Query: "q=1+UNION%20SELECT+2"})); got != "sqli-union" {
		t.Errorf("union: %q", got)
	}
	// Route suffix (mounted under /blog), method, every match.
	if got := ids(m.MatchRecord(AccessRecord{Method: "POST", Path: "/blog/wp-admin/admin-ajax.php", Query: "action=evil_action&id=1%27"})); got != "wp-ajax-x" {
		t.Errorf("route, method, both params: %q", got)
	}
	if got := ids(m.MatchRecord(AccessRecord{Method: "PUT", Path: "/wp-admin/admin-ajax.php", Query: "action=evil_action&id=1%27"})); got != "" {
		t.Errorf("method not on the route: %q", got)
	}
	if got := ids(m.MatchRecord(AccessRecord{Method: "GET", Path: "/wp-admin/admin-ajax.php", Query: "action=evil_action&id=1"})); got != "" {
		t.Errorf("one match missing: %q", got)
	}
	r := m.Match(Normalize(AccessRecord{Method: "GET", Path: "/app/.env"}))
	if len(r.Hits) != 1 || !r.Hits[0].RouteOnly {
		t.Errorf("route only: %+v", r.Hits)
	}
	// An ambiguous record's other split is matched too.
	amb := AccessRecord{Method: "GET", Path: "/fake", Alts: []AccessRecord{{Method: "GET", Path: "/real", Query: "x=union select 1"}}}
	if got := ids(m.MatchRecord(amb)); got != "sqli-union" {
		t.Errorf("Alts: %q", got)
	}
	// The same request names the same parameter every time.
	q := Normalize(AccessRecord{Method: "GET", Path: "/", Query: "b=union select 1&a=union select 2"})
	for i := 0; i < 20; i++ {
		if h := m.Match(q).Hits; h[0].Param != "a" {
			t.Fatalf("param %q, want a", h[0].Param)
		}
	}
}

// A request matched longer than MaxMatchTime is said so, and every
// signature is tried all the same (review B-1: the clock no longer stops
// matching; the input's length bounds it).
func TestMatchTimeBound(t *testing.T) {
	m := NewMatcher(loadSigs(t, matchSigs))
	clock := time.Unix(0, 0)
	m.now = func() time.Time { clock = clock.Add(2 * MaxMatchTime); return clock }
	r := m.Match(Normalize(AccessRecord{Method: "GET", Path: "/.env", Query: "q=union select 1"}))
	if !r.TimedOut || len(r.Hits) != 2 {
		t.Errorf("%+v: want timed out, both signatures tried", r)
	}
}

// Security review on b38ec2f: what the server routes and reads, not the
// text as written; and the evidence as the request sent it.
func TestMatchAsServersRead(t *testing.T) {
	m := NewMatcher(loadSigs(t, matchSigs))
	hit := func(r AccessRecord) []Hit {
		var hs []Hit
		for _, res := range m.MatchRecord(r) {
			hs = append(hs, res.Hits...)
		}
		return hs
	}
	for _, p := range []string{"/wp-admin/admin-ajax.php;jsessionid=1", "/wp-admin/admin-ajax.php.", "/wp-admin/admin-ajax.php::$DATA", "/wp-admin/admin-ajax.php/extra"} {
		if hs := hit(AccessRecord{Method: "GET", Path: p, Query: "action=evil_action&id=1'"}); len(hs) != 1 || hs[0].Signature != "wp-ajax-x" {
			t.Errorf("%s: %+v", p, hs)
		}
	}
	if hs := hit(AccessRecord{Method: "GET", Path: "/wp-admin/admin-ajax.php", Query: "action=evil_action&id[]=1'"}); len(hs) != 1 {
		t.Errorf("id[]: %+v (PHP reads it as id)", hs)
	}
	php := NewMatcher(loadSigs(t, `
[[signature]]
id = "user-id"
title = "t"
class = "sqli"
source = "shentu"
license = "Apache-2.0"
[[signature.match]]
part = "param"
param = "user_id"
contains = ["'"]
`))
	for _, q := range []string{"user.id=1'", "user id=1'", "user[id=1'", "user_id=1'"} {
		if r := php.Match(Normalize(AccessRecord{Method: "GET", Path: "/", Query: q})); len(r.Hits) != 1 {
			t.Errorf("%s: %+v (PHP reads it as user_id)", q, r.Hits)
		}
	}
	hs := hit(AccessRecord{Method: "GET", Path: "/x", Query: "Q=1%20UNION%20SeLeCt%202"})
	if len(hs) != 1 || hs[0].Raw != "1%20UNION%20SeLeCt%202" || !strings.Contains(hs[0].Excerpt, "union select") {
		t.Errorf("evidence: %+v", hs)
	}
	long := Normalize(AccessRecord{Path: "/", Query: "k=" + strings.Repeat("%41", MaxNormalized)})
	if !long.Cut {
		t.Error("a parameter value past MaxNormalized is not said cut (its decoded form is shorter)")
	}
}
