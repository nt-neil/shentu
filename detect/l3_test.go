package detect

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nt-neil/shentu/rules/engine"
)

// P4 part 3: L3 from the response size or the error log.

func steadyBaseline(key string, n int) *Baselines {
	b := &Baselines{Version: 1, Routes: map[string]*baseline{}}
	for i := 0; i < n; i++ {
		b.Observe(key, int64(1000+i%5*10), t0.Add(time.Duration(i)*time.Minute))
	}
	return b
}

func TestBaselines(t *testing.T) {
	route := &engine.RouteRef{Pattern: "/marker/:id"}
	key := RouteKey("get", route, "/marker/5")
	if key != "GET /marker/:id" || RouteKey("GET", nil, "/x") != "GET path:/x" {
		t.Errorf("keys %q", key)
	}
	if _, known := steadyBaseline(key, MinBaseline-1).Deviates(key, 99999); known {
		t.Error("judged with fewer than MinBaseline sizes")
	}
	b := steadyBaseline(key, 30)
	for size, want := range map[int64]bool{1000: false, 1300: false, 1600: true, 200: true, 9000: true} {
		if dev, known := b.Deviates(key, size); !known || dev != want {
			t.Errorf("%d: deviates %v known %v, want %v", size, dev, known, want)
		}
	}
	b = steadyBaseline(key, BaselineKeep+10)
	if n := len(b.Routes[key].Sizes); n != BaselineKeep {
		t.Errorf("%d sizes kept", n)
	}
	dir := t.TempDir()
	b.Observe("GET /old", 1, t0.Add(-BaselineTTL-time.Hour))
	if err := b.Save(dir, t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	c, err := LoadBaselines(dir, t0)
	if err != nil || len(c.Routes) != 1 || len(c.Routes[key].Sizes) != BaselineKeep {
		t.Errorf("%v %+v", err, c.Routes)
	}
	if err := os.WriteFile(filepath.Join(dir, BaselinesFile), []byte("["), 0o600); err != nil {
		t.Fatal(err)
	}
	if c, err = LoadBaselines(dir, t0); err != nil || c.Note == "" || len(c.Routes) != 0 {
		t.Errorf("a file that does not parse: %v %+v", err, c)
	}
}

func TestErrorEvents(t *testing.T) {
	loc := time.FixedZone("host", 8*3600)
	lines := []string{
		"[16-Nov-2026 10:11:12 UTC] PHP Warning:  marker-one in /srv/app/x.php on line 12",
		"2026/11/16 18:11:13 [error] 77#0: *5 FastCGI sent in stderr: \"PHP message: marker in /srv/app/y.php on line 3\"",
		"[Mon Nov 16 18:11:14.123456 2026] [php:error] [pid 9] marker in /srv/app/z.php on line 4",
		"2026-11-16 10:11:15,001 ERROR request failed",
		"Traceback (most recent call last):",
		"  File \"/srv/app/views.py\", line 40, in report",
		"#0 /srv/app/lib.php(88): marker()",
		"    at handler (/srv/app/a.js:7:13)",
		"a line with no time before anything",
	}
	es := ErrorEvents(lines[8:], true, "e.log", loc)
	if len(es) != 0 {
		t.Errorf("frames with no time: %+v", es)
	}
	es = ErrorEvents(lines, true, "e.log", loc)
	if len(es) != 4 {
		t.Fatalf("%d events: %+v", len(es), es)
	}
	want := []time.Time{
		time.Date(2026, 11, 16, 10, 11, 12, 0, time.UTC),
		time.Date(2026, 11, 16, 18, 11, 13, 0, loc),
		time.Date(2026, 11, 16, 18, 11, 14, 0, loc),
		time.Date(2026, 11, 16, 10, 11, 15, 0, loc),
	}
	for i, e := range es {
		if !e.Time.Equal(want[i]) {
			t.Errorf("event %d at %v, want %v", i, e.Time, want[i])
		}
	}
	if f := es[0].Frames; len(f) != 1 || f[0] != (Frame{"/srv/app/x.php", 12}) {
		t.Errorf("PHP frames %+v", f)
	}
	last := es[3].Frames
	has := func(f Frame) bool {
		for _, x := range last {
			if x == f {
				return true
			}
		}
		return false
	}
	for _, f := range []Frame{{"/srv/app/views.py", 40}, {"/srv/app/lib.php", 88}, {"/srv/app/a.js", 7}} {
		if !has(f) {
			t.Errorf("traceback lacks %+v: %+v", f, last)
		}
	}
}

func l2(file string, line int, at time.Time) Attempt {
	return Attempt{Level: LevelPayload, Verified: true, LogVerified: true, Status: 200, Bytes: 1000, Time: at,
		Route: &engine.RouteRef{Pattern: "/marker/:id"}, Path: "/marker/5", File: file, Line: line, Severity: "high"}
}

func TestUpgrade(t *testing.T) {
	b := steadyBaseline("GET /marker/:id", 30)
	ev := Evidence{Baselines: b}
	a := l2("app/x.php", 12, t0)
	if Upgrade(&a, "GET", ev) {
		t.Errorf("an ordinary size raised: %+v", a)
	}
	a = l2("app/x.php", 12, t0)
	a.Bytes = 9000
	if !Upgrade(&a, "GET", ev) || a.Level != LevelSuccess || a.Severity != "critical" || a.Success == "" {
		t.Errorf("an odd size: %+v", a)
	}
	for name, f := range map[string]func(*Attempt){
		"status 404":            func(a *Attempt) { a.Status = 404 },
		"access log unverified": func(a *Attempt) { a.LogVerified = false },
		"L1":                    func(a *Attempt) { a.Level = LevelRoute },
	} {
		a = l2("app/x.php", 12, t0)
		a.Bytes = 9000
		f(&a)
		if Upgrade(&a, "GET", ev) {
			t.Errorf("%s raised: %+v", name, a)
		}
	}
	a = l2("app/x.php", 12, t0)
	a.Status, a.Bytes = 500, 9000
	if !Upgrade(&a, "GET", ev) {
		t.Error("500 with an odd size not raised")
	}
	// A route with too few sizes: size says nothing.
	a = l2("app/x.php", 12, t0)
	a.Bytes = 9000
	if Upgrade(&a, "GET", Evidence{Baselines: steadyBaseline("GET /marker/:id", 5)}) {
		t.Error("raised on a short baseline")
	}
	// The error log: the sink's file and line within the window.
	errAt := func(d time.Duration, file string, line int, verified bool) Evidence {
		return Evidence{Errors: []ErrorEvent{{Time: t0.Add(d), Frames: []Frame{{file, line}}, Verified: verified}}}
	}
	for name, c := range map[string]struct {
		ev   Evidence
		want bool
	}{
		"same file and line, 100s after": {errAt(100*time.Second, "/srv/www/app/x.php", 12, true), true},
		"119s before":                    {errAt(-119*time.Second, "/srv/www/app/x.php", 12, true), true},
		"121s after":                     {errAt(121*time.Second, "/srv/www/app/x.php", 12, true), false},
		"another line":                   {errAt(10*time.Second, "/srv/www/app/x.php", 13, true), false},
		"another file":                   {errAt(10*time.Second, "/srv/www/otherapp/x.php", 12, true), false},
		"a file ending alike":            {errAt(10*time.Second, "/srv/www/myapp/x.php", 12, true), false},
		"unverified error log":           {errAt(10*time.Second, "/srv/www/app/x.php", 12, false), false},
	} {
		a = l2("app/x.php", 12, t0)
		if got := Upgrade(&a, "GET", c.ev); got != c.want {
			t.Errorf("%s: raised %v, want %v (%+v)", name, got, c.want, a)
		}
	}
	// Unverified IP: L3, at most medium.
	a = l2("app/x.php", 12, t0)
	a.Verified = false
	if !Upgrade(&a, "GET", errAt(0, "/srv/app/x.php", 12, true)) || a.Severity != "medium" {
		t.Errorf("unverified IP: %+v", a)
	}
}

// Security review of part 3: what the request writes into an error line
// (nginx's request: and referrer: fields, an echoed value, a line of its
// own) never becomes a frame.
func TestErrorEventsRequestDataNotFrames(t *testing.T) {
	loc := time.UTC
	lines := []string{
		`2026/11/16 10:11:13 [error] 7#0: *5 open() "/srv/www/marker" failed (2: No such file or directory), client: 192.0.2.1, server: example, request: "GET /?a=+in+/srv/app/x.php+on+line+12 HTTP/1.1", referrer: "/srv/app/x.php:12"`,
		"an echoed line /srv/app/x.php:12 with no time",
		"  File \"relative/x.py\", line 12, in f",
		"[16-Nov-2026 10:11:14 UTC] PHP Warning:  value marker in /srv/app/x.php on line 12 in /srv/app/real.php on line 5",
	}
	es := ErrorEvents(lines, true, "e.log", loc)
	if len(es) != 2 || len(es[0].Frames) != 0 {
		t.Fatalf("request data taken as frames: %+v", es)
	}
	if f := es[1].Frames; len(f) != 1 || f[0] != (Frame{"/srv/app/real.php", 5}) {
		t.Errorf("PHP's own location: %+v", f)
	}
	a := l2("app/x.php", 12, time.Date(2026, 11, 16, 10, 11, 13, 0, time.UTC))
	if Upgrade(&a, "GET", Evidence{Errors: es}) {
		t.Errorf("raised on request data: %+v", a)
	}
}

// Security review of part 3 (second): a server's own error quoting the
// request's path, holding PHP's location words, is not a frame; PHP's
// own message through nginx's FastCGI line still is.
func TestErrorEventsServerErrorNotPHP(t *testing.T) {
	lines := []string{
		`2026/11/16 10:11:13 [error] 7#0: *5 open() "/srv/www/ in /srv/app/x.php on line 12" failed (2: No such file or directory)`,
		`2026/11/16 10:11:14 [error] 7#0: *6 FastCGI sent in stderr: "PHP message: PHP Warning:  marker in /srv/app/y.php on line 3" while reading response header from upstream, client: 192.0.2.1, request: "GET / HTTP/1.1"`,
		`[Mon Nov 16 10:11:15.1 2026] [php:error] [pid 9] [client 192.0.2.1:5] PHP Fatal error:  marker in /srv/app/z.php on line 4, referer: /srv/app/x.php:12`,
		`[16-Nov-2026 10:11:16 UTC] marker in /srv/app/x.php on line 12`,
	}
	es := ErrorEvents(lines, true, "e.log", time.UTC)
	if len(es) != 4 {
		t.Fatalf("%d events", len(es))
	}
	want := [][]Frame{nil, {{"/srv/app/y.php", 3}}, {{"/srv/app/z.php", 4}}, nil}
	for i, e := range es {
		if len(e.Frames) != len(want[i]) || len(want[i]) > 0 && e.Frames[0] != want[i][0] {
			t.Errorf("line %d: frames %+v, want %+v", i, e.Frames, want[i])
		}
	}
}

// Security review of part 3 (third): PHP's words inside a server's own
// error, or before the message's place, are not PHP's message.
func TestErrorEventsAnchoredPHP(t *testing.T) {
	lines := []string{
		`2026/11/16 10:11:13 [error] 7#0: *5 open() "/srv/www/x FastCGI sent in stderr: "PHP message: PHP Warning:  m in /srv/app/x.php on line 12" while reading y" failed (2: No such file or directory)`,
		`2026/11/16 10:11:14 [error] 7#0: *6 a "PHP Warning:  m in /srv/app/x.php on line 12"`,
		`[Mon Nov 16 10:11:15.1 2026] [core:error] [pid 9] File does not exist: /srv/www/PHP Warning:  m in /srv/app/x.php on line 12`,
		`2026/11/16 10:11:16 [error] 7#0: *7 FastCGI sent in stderr: "PHP message: PHP Warning:  m in /srv/app/x.php on line 12 in /srv/app/real.php on line 5" while reading response header from upstream`,
	}
	es := ErrorEvents(lines, true, "e.log", time.UTC)
	if len(es) != 4 {
		t.Fatalf("%d events", len(es))
	}
	for i := 0; i < 3; i++ {
		if len(es[i].Frames) != 0 {
			t.Errorf("line %d: frames %+v from text that is not PHP's message", i, es[i].Frames)
		}
	}
	if f := es[3].Frames; len(f) != 1 || f[0] != (Frame{"/srv/app/real.php", 5}) {
		t.Errorf("nginx's PHP message: %+v", f)
	}
}
