package hostenv

import (
	"strings"
	"testing"
)

// CVE-2026-123007 and CVE-2026-123633 reach only a server that speaks HTTP/2.
func TestNginxHTTP2(t *testing.T) {
	for _, c := range []struct {
		why, conf, site string
		on              bool
	}{
		{"listen with http2", "http {\n  include /etc/nginx/conf.d/*.conf;\n}\n", "server {\n  listen 443 ssl http2;\n}\n", true},
		{"http2 on in the server", "http {\n  include /etc/nginx/conf.d/*.conf;\n}\n", "server {\n  listen 443 ssl;\n  http2 on;\n}\n", true},
		{"http2 on in http, inherited", "http {\n  http2 on;\n  include /etc/nginx/conf.d/*.conf;\n}\n", "server {\n  listen 443 ssl;\n}\n", true},
		{"http2 on in http, off in the only server", "http {\n  http2 on;\n  include /etc/nginx/conf.d/*.conf;\n}\n", "server {\n  listen 443 ssl;\n  http2 off;\n}\n", false},
		{"listen http2 wins over http2 off", "http {\n  include /etc/nginx/conf.d/*.conf;\n}\n", "server {\n  listen 443 ssl http2;\n  http2 off;\n}\n", true},
		{"HTTP/1.1 only", "http {\n  include /etc/nginx/conf.d/*.conf;\n}\n", "server {\n  listen 443 ssl;\n}\n", false},
		{"commented out", "http {\n  include /etc/nginx/conf.d/*.conf;\n}\n", "server {\n  # listen 443 ssl http2;\n  # http2 on;\n  listen 443 ssl;\n}\n", false},
		{"quic is HTTP/3", "http {\n  include /etc/nginx/conf.d/*.conf;\n}\n", "server {\n  listen 443 quic reuseport;\n}\n", false},
		{"http2 in a stream block is not HTTP", "stream {\n  include /etc/nginx/conf.d/*.conf;\n}\nhttp {\n}\n", "server {\n  listen 443 http2;\n}\n", false},
	} {
		h := newFake(true)
		h.files["/etc/nginx/nginx.conf"] = c.conf
		h.files["/etc/nginx/conf.d/site.conf"] = c.site
		on, found, unread := NginxHTTP2(h)
		if on != c.on || !found || len(unread) != 0 {
			t.Errorf("%s: on %v found %v unread %v, want on %v", c.why, on, found, unread, c.on)
		}
	}
	if _, found, _ := NginxHTTP2(newFake(true)); found {
		t.Error("no nginx.conf: found")
	}
	// A file that cannot be read may be the one turning HTTP/2 on.
	h := newFake(true)
	h.files["/etc/nginx/nginx.conf"] = "http {\n  include /etc/nginx/conf.d/*.conf;\n}\n"
	h.files["/etc/nginx/conf.d/site.conf"] = "server {\n  listen 443 ssl http2;\n}\n"
	h.denied["/etc/nginx/conf.d/site.conf"] = true
	if on, found, unread := NginxHTTP2(h); on || !found || len(unread) != 1 || !strings.Contains(unread[0], "site.conf") {
		t.Errorf("unreadable site: on %v found %v unread %v", on, found, unread)
	}
}

// OpenResty's configuration is under its own prefix: its relative includes
// are there too (review 2 S-3).
func TestNginxHTTP2OpenResty(t *testing.T) {
	h := newFake(true)
	h.files[OpenRestyConf] = "http {\n  include conf.d/*.conf;\n}\n"
	h.files["/usr/local/openresty/nginx/conf/conf.d/site.conf"] = "server {\n  listen 443 ssl;\n  http2 on;\n}\n"
	if on, found, unread := NginxHTTP2At(h, OpenRestyConf); !on || !found || len(unread) != 0 {
		t.Errorf("OpenResty: on %v found %v unread %v", on, found, unread)
	}
	if _, found, _ := NginxHTTP2(h); found {
		t.Error("OpenResty only: /etc/nginx/nginx.conf found")
	}
	// an include outside its prefix is not read: may be the one turning HTTP/2 on
	h.files[OpenRestyConf] = "http {\n  include /etc/elsewhere/site.conf;\n}\n"
	h.files["/etc/elsewhere/site.conf"] = "server {\n  listen 443 http2;\n}\n"
	if on, _, unread := NginxHTTP2At(h, OpenRestyConf); on || len(unread) != 1 {
		t.Errorf("include outside the prefix: on %v unread %v", on, unread)
	}
}
