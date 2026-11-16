package detect

import (
	"errors"
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
	if !ok || r.Host != "shop.test" || r.Client != "203.0.113.7" || r.User != "bob" || r.Path != "/index.php" || r.Query != "page=../../etc/passwd" ||
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
