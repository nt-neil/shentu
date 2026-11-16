package detect

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nt-neil/shentu/hostenv"
)

const ngxCombinedSpec = `$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"`

func TestNginxCombined(t *testing.T) {
	p, err := NginxParser(ngxCombinedSpec, "")
	if err != nil {
		t.Fatal(err)
	}
	r, ok := p.Parse([]byte(`203.0.113.7 - - [15/Nov/2026:10:11:12 +0800] "GET /wp-admin/admin-ajax.php?action=x&id=1%27 HTTP/1.1" 200 512 "-" "sqlmap/1.8 \x22q\x22"`))
	if !ok {
		t.Fatal("not parsed")
	}
	want := AccessRecord{Client: "203.0.113.7", Time: time.Date(2026, 11, 15, 2, 11, 12, 0, time.UTC),
		Request: "GET /wp-admin/admin-ajax.php?action=x&id=1%27 HTTP/1.1", Method: "GET", Path: "/wp-admin/admin-ajax.php",
		Query: "action=x&id=1%27", Proto: "HTTP/1.1", Status: 200, Bytes: 512, UserAgent: `sqlmap/1.8 "q"`}
	if r != want {
		t.Errorf("got  %+v\nwant %+v", r, want)
	}
	// Junk a scanner sends instead of a request line: kept, not split.
	r, ok = p.Parse([]byte(`198.51.100.9 - - [15/Nov/2026:10:11:12 +0800] "\x16\x03\x01" 400 157 "-" "-"`))
	if !ok || r.Request != "\x16\x03\x01" || r.Method != "" || r.Status != 400 {
		t.Errorf("junk request %+v %v", r, ok)
	}
	for _, bad := range []string{
		`203.0.113.7 - - [15/Nov/2026:10:11:12 +0800] "GET / HTTP/1.1" 2OO 512 "-" "-"`, // not a status
		`203.0.113.7 - - [yesterday] "GET / HTTP/1.1" 200 512 "-" "-"`,
		`203.0.113.7 - - [15/Nov/2026:10:11:12 +0800] "GET / HTTP/1.1" 200 512 "-"`,          // cut short
		`203.0.113.7 - - [15/Nov/2026:10:11:12 +0800] "GET / HTTP/1.1" 200 512 "-" "-" more`, // more than the format
		`203.0.113.7 - - [15/Nov/2026:10:11:12 +0800] "GET /\q HTTP/1.1" 200 512 "-" "-"`,    // an escape nginx does not write
	} {
		if _, ok := p.Parse([]byte(bad)); ok {
			t.Errorf("parsed a line not in the format: %s", bad)
		}
	}
}

func TestNginxJSON(t *testing.T) {
	p, err := NginxParser(`{"ip":"$remote_addr","t":"$time_iso8601","m":"$request_method","u":"$request_uri","s":$status,"ua":"${http_user_agent}"}`, "json")
	if err != nil {
		t.Fatal(err)
	}
	r, ok := p.Parse([]byte(`{"ip":"2001:db8::1","t":"2026-11-15T10:11:12+08:00","m":"POST","u":"/api/run?cmd=%3Bid","s":500,"ua":"curl \"x\" é"}`))
	if !ok || r.Client != "2001:db8::1" || r.Method != "POST" || r.Path != "/api/run" || r.Query != "cmd=%3Bid" || r.Status != 500 ||
		r.UserAgent != `curl "x" é` || !r.Time.Equal(time.Date(2026, 11, 15, 2, 11, 12, 0, time.UTC)) {
		t.Errorf("%+v %v", r, ok)
	}
}

func TestApacheFormats(t *testing.T) {
	p, err := ApacheParser(`%v:%p %h %l %u %t "%r" %>s %O "%{Referer}i" "%{User-Agent}i"`)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := p.Parse([]byte(`shop.test:443 203.0.113.7 - bob [15/Nov/2026:10:11:12 +0800] "GET /index.php?page=../../etc/passwd HTTP/1.1" 200 1043 "https://shop.test/" "Mozilla/5.0 \"x\""`))
	if !ok || r.Vhost != "shop.test" || r.Client != "203.0.113.7" || r.User != "bob" || r.Path != "/index.php" || r.Query != "page=../../etc/passwd" ||
		r.Status != 200 || r.Bytes != 1043 || r.Referer != "https://shop.test/" || r.UserAgent != `Mozilla/5.0 "x"` || r.Time.IsZero() {
		t.Errorf("vhost_combined %+v %v", r, ok)
	}
	p, err = ApacheParser(`%a %t %m %U%q %400,501{X-Forwarded-For}i %s %b`)
	if err != nil {
		t.Fatal(err)
	}
	r, ok = p.Parse([]byte(`10.0.0.2 [15/Nov/2026:10:11:12 +0800] GET /a?b=1 - 404 -`))
	if !ok || r.Method != "GET" || r.Path != "/a" || r.Query != "b=1" || r.Status != 404 || r.Bytes != 0 {
		t.Errorf("method, path and query apart %+v %v", r, ok)
	}
}

// Formats detect would have to guess at are refused, with why.
func TestFormatUnrecognized(t *testing.T) {
	for name, f := range map[string]func() (*Parser, error){
		"two fields side by side": func() (*Parser, error) { return NginxParser(`$remote_addr$status "$request"`, "") },
		"no status":               func() (*Parser, error) { return NginxParser(`$remote_addr "$request"`, "") },
		"no client":               func() (*Parser, error) { return ApacheParser(`%t "%r" %>s`) },
		"strftime time":           func() (*Parser, error) { return ApacheParser(`%h %{%Y-%m-%d}t "%r" %>s`) },
		"unknown escape":          func() (*Parser, error) { return NginxParser(ngxCombinedSpec, "base64") },
		"escape=none":             func() (*Parser, error) { return NginxParser(ngxCombinedSpec, "none") },
		"name defined nowhere": func() (*Parser, error) {
			return ParserFor(hostenv.LogSource{Server: "nginx", Kind: "access", Format: "custom"})
		},
		"php-fpm access": func() (*Parser, error) {
			return ParserFor(hostenv.LogSource{Server: "php-fpm", Kind: "access", Spec: "%R - %u"})
		},
		"error log": func() (*Parser, error) { return ParserFor(hostenv.LogSource{Server: "nginx", Kind: "error"}) },
	} {
		if _, err := f(); !errors.Is(err, ErrFormatUnrecognized) {
			t.Errorf("%s: %v, want format_unrecognized", name, err)
		}
	}
	if _, err := ParserFor(hostenv.LogSource{Server: "nginx", Kind: "access", Format: "combined", Spec: ngxCombinedSpec}); err != nil {
		t.Errorf("combined from hostenv: %v", err)
	}
}

// B-2: a header the request writes, before the client address, could make
// the address anything: such a format is refused, and a client that is not
// an address makes the line unparsed.
func TestClientNotForgeable(t *testing.T) {
	for _, spec := range []string{
		`$http_x_forwarded_for $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent`,
		`$http_host $remote_addr [$time_local] "$request" $status`,
		`$http_x_custom $remote_addr [$time_local] "$request" $status`, // a variable detect does not read: not trusted either
	} {
		if _, err := NginxParser(spec, ""); !errors.Is(err, ErrFormatUnrecognized) {
			t.Errorf("%s: %v, want format_unrecognized", spec, err)
		}
	}
	if _, err := ApacheParser(`%v:%p %h %l %u %t "%r" %>s %O`); err != nil {
		t.Errorf("vhost_combined: %v (ServerName and port are not the request's)", err)
	}
	p, _ := NginxParser(ngxCombinedSpec, "")
	if _, ok := p.Parse([]byte(`example.com - - [15/Nov/2026:10:11:12 +0800] "GET / HTTP/1.1" 200 1 "-" "-"`)); ok || p.Unparsed != 1 {
		t.Errorf("a client that is not an address was parsed (unparsed %d)", p.Unparsed)
	}
	if r, ok := p.Parse([]byte(`unix: - - [15/Nov/2026:10:11:12 +0800] "GET / HTTP/1.1" 200 1 "-" "-"`)); !ok || r.Client != "" {
		t.Errorf("unix socket client: %+v %v", r, ok)
	}
}

// N-5: what an attacker sends cannot make his own line unparseable.
func TestParseNotEvadable(t *testing.T) {
	p, _ := NginxParser(ngxCombinedSpec, "")
	// A Basic auth user "x [" (spaces are not escaped): the user field
	// backtracks to the real " [".
	r, ok := p.Parse([]byte(`203.0.113.7 - x [ [15/Nov/2026:10:11:12 +0800] "GET /?id=1%27 HTTP/1.1" 200 1 "-" "-"`))
	if !ok || r.User != "x [" || r.Path != "/" || r.Status != 200 {
		t.Errorf("user with ' [': %+v %v", r, ok)
	}
	a, _ := ApacheParser(`%h %l %u %t "%r" %>s %b`)
	if r, ok := a.Parse([]byte(`203.0.113.7 - a b [15/Nov/2026:10:11:12 +0800] "GET / HTTP/1.1" 200 5`)); !ok || r.User != "a b" {
		t.Errorf("Apache %%u with a space: %+v %v", r, ok)
	}
	j, _ := NginxParser(`{"ip":"$remote_addr","t":"$time_iso8601","r":"$request","s":$status,"ua":"$http_user_agent"}`, "json")
	if r, ok := j.Parse([]byte("{\"ip\":\"203.0.113.7\",\"t\":\"2026-11-15T10:11:12+08:00\",\"r\":\"GET / HTTP/1.1\",\"s\":200,\"ua\":\"\xff\xfe\"}")); !ok || r.Client != "203.0.113.7" {
		t.Errorf("json with raw 0xff: %+v %v", r, ok)
	}
	// A 5KB 0xff User-Agent is 20KB escaped: cut at MaxLine, the line still
	// names who asked for what.
	line := `203.0.113.7 - - [15/Nov/2026:10:11:12 +0800] "GET /x.php?c=;id HTTP/1.1" 200 1 "-" "` + strings.Repeat(`\xFF`, 5000)
	line = line[:MaxLine]
	if _, ok := p.Parse([]byte(line)); ok {
		t.Error("a cut line parsed as whole")
	}
	r, ok = p.ParseCut([]byte(line))
	if !ok || !r.Cut || r.Client != "203.0.113.7" || r.Path != "/x.php" || r.Time.IsZero() {
		t.Errorf("cut line: %+v %v", r, ok)
	}
	// Cut inside the request (a padded URL): its start is still the request.
	if r, ok := p.ParseCut([]byte(`203.0.113.7 - - [15/Nov/2026:10:11:12 +0800] "GET /` + strings.Repeat("a", 100))); !ok || !r.Cut || r.Method != "GET" {
		t.Errorf("cut inside the request: %+v %v", r, ok)
	}
	// Cut before the request: not enough to match.
	if _, ok := p.ParseCut([]byte(`203.0.113.7 - - [15/Nov/20`)); ok {
		t.Error("a line cut before the request was taken")
	}
}

// N-10: with HostnameLookups on, %h is a PTR name its zone's owner writes.
func TestApacheHostnameLookups(t *testing.T) {
	src := hostenv.LogSource{Server: "apache", Kind: "access", Spec: `%h %l %u %t "%r" %>s %b`, HostnameLookups: true}
	if _, err := ParserFor(src); !errors.Is(err, ErrFormatUnrecognized) {
		t.Errorf("%%h with HostnameLookups On: %v", err)
	}
	src.Spec = `%a %l %u %t "%r" %>s %b`
	if _, err := ParserFor(src); err != nil {
		t.Errorf("%%a with HostnameLookups On: %v", err)
	}
}

// Review 2, N-1: more of the next literal than the split from the start
// will try (a Basic auth user "x" and 200 " [", an Apache %u with 200
// spaces): split from the end, matched, flagged Suspicious.
func TestParseManyLiterals(t *testing.T) {
	p, _ := NginxParser(ngxCombinedSpec, "")
	line := `203.0.113.7 - x` + strings.Repeat(" [", 200) + ` [15/Nov/2026:10:11:12 +0800] "GET /?id=1%27 HTTP/1.1" 200 1 "-" "-"`
	r, ok := p.Parse([]byte(line))
	if !ok || !r.Suspicious || r.Client != "203.0.113.7" || r.Path != "/" || r.Query != "id=1%27" || r.Time.IsZero() || p.Suspicious != 1 {
		t.Errorf("nginx: %+v %v (suspicious %d)", r, ok, p.Suspicious)
	}
	a, _ := ApacheParser(`%h %l %u %t "%r" %>s %b`)
	r, ok = a.Parse([]byte(`203.0.113.7 - a` + strings.Repeat(" ", 200) + `b [15/Nov/2026:10:11:12 +0800] "GET /x HTTP/1.1" 200 5`))
	if !ok || r.Path != "/x" || r.Client != "203.0.113.7" {
		t.Errorf("apache: %+v %v", r, ok)
	}
}

// Review 2, N-2: a cut falling inside an escape does not lose the line.
func TestParseCutInsideEscape(t *testing.T) {
	p, _ := NginxParser(ngxCombinedSpec, "")
	for _, tail := range []string{`\xF`, `\x`, `\`} {
		line := `203.0.113.7 - - [15/Nov/2026:10:11:12 +0800] "GET /a?q=` + strings.Repeat(`\xFF`, 10) + tail
		if r, ok := p.ParseCut([]byte(line)); !ok || !r.Cut || r.Path != "/a" {
			t.Errorf("cut at %q: %+v %v", tail, r, ok)
		}
	}
	j, _ := NginxParser(`{"ip":"$remote_addr","t":"$time_iso8601","r":"$request","s":$status}`, "json")
	if r, ok := j.ParseCut([]byte(`{"ip":"203.0.113.7","t":"2026-11-15T10:11:12+08:00","r":"GET /b?x=\u00`)); !ok || r.Path != "/b" {
		t.Errorf("json cut inside \\u: %+v %v", r, ok)
	}
}

// Review 2, N-3: a field the client writes before the request holding a
// forged line end splits two ways: both requests are kept.
func TestParseAmbiguous(t *testing.T) {
	p, err := NginxParser(`$remote_addr $remote_user $request_uri $status $request_time`, "")
	if err != nil {
		t.Fatal(err)
	}
	r, ok := p.Parse([]byte(`203.0.113.7 a /fake 200 /real 404 0.003`))
	if !ok || !r.Ambiguous || r.Alt == nil || p.Ambiguous != 1 {
		t.Fatalf("%+v %v", r, ok)
	}
	paths := map[string]bool{r.Path: true, r.Alt.Path: true}
	if !paths["/fake"] || !paths["/real"] {
		t.Errorf("the two requests: %q and %q", r.Path, r.Alt.Path)
	}
}

// Review 2, N-4: $remote_addr:$remote_port cannot be split for IPv6.
func TestClientFollowedByColon(t *testing.T) {
	if _, err := NginxParser(`$remote_addr:$remote_port [$time_local] "$request" $status`, ""); !errors.Is(err, ErrFormatUnrecognized) {
		t.Errorf("%v, want format_unrecognized", err)
	}
}
