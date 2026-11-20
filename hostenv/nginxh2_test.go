package hostenv

import (
	"io/fs"
	"path"
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

// A directory on the way that links outside the prefix: what the file there
// says is not trusted, so it counts as not read and the result fails closed
// (review of #107 S-1).
func TestNginxHTTP2LinkedDir(t *testing.T) {
	for _, conf := range []string{OpenRestyConf, NginxConf} {
		h := newFake(true)
		dir := path.Dir(conf)
		h.files[conf] = "http {\n  http2 on;\n  include sites/site.conf;\n}\n"
		h.links[dir+"/sites"] = "/home/u/sites"
		site := "server {\n  listen 443 ssl;\n  http2 off;\n}\n"
		h.files[dir+"/sites/site.conf"], h.files["/home/u/sites/site.conf"] = site, site // the system follows the linked directory
		on, found, unread := NginxHTTP2At(h, conf)
		if on || !found || len(unread) != 1 || !strings.Contains(unread[0], "sites/site.conf") {
			t.Errorf("%s: on %v found %v unread %v, want the linked file not read", conf, on, found, unread)
		}
		h.links = map[string]string{} // a real directory inside the prefix: read
		if _, _, unread := NginxHTTP2At(h, conf); len(unread) != 0 {
			t.Errorf("%s, no link: unread %v", conf, unread)
		}
	}
}

// A linked directory inside the prefix is trusted only as WebLogs trusts a
// file: root's and not writable by others, and so every directory above it
// (security review of a6390c2).
func TestNginxHTTP2LinkedDirOwner(t *testing.T) {
	const nginx = "/usr/local/openresty/nginx"
	for _, c := range []struct {
		why, target string
		owner       int
		mode        fs.FileMode
		unread      bool
	}{
		{"a directory a user owns", nginx + "/drop", 1000, 0o755, true},
		{"a directory others may write", nginx + "/drop", 0, 0o777, true},
		{"root's directory", nginx + "/shared", 0, 0o755, false},
	} {
		h := logHost()
		for _, d := range []string{"/usr", "/usr/local", "/usr/local/openresty", nginx, nginx + "/conf"} {
			h.st[d] = FileStat{Mode: fs.ModeDir | 0o755, UID: 0}
		}
		h.st[c.target] = FileStat{Mode: fs.ModeDir | c.mode, UID: c.owner}
		h.files[OpenRestyConf] = "http {\n  http2 on;\n  include sites/site.conf;\n}\n"
		h.links[nginx+"/conf/sites"] = c.target
		site := "server {\n  listen 443 ssl;\n  http2 off;\n}\n"
		h.files[nginx+"/conf/sites/site.conf"], h.files[c.target+"/site.conf"] = site, site // the system follows the linked directory
		h.st[c.target+"/site.conf"] = FileStat{Mode: 0o644, UID: 0}
		on, found, unread := NginxHTTP2At(h, OpenRestyConf)
		if on || !found || (len(unread) == 1) != c.unread {
			t.Errorf("%s: on %v found %v unread %v, want unread %v", c.why, on, found, unread, c.unread)
		}
	}
}
