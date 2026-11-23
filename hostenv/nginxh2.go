package hostenv

import (
	"path"
	"slices"
	"strings"
)

// NginxHTTP2 reads nginx's configuration as WebLogs does (/etc/nginx/nginx.conf
// and what it includes) and reports whether a server of it speaks HTTP/2: a
// listen with the http2 parameter, or http2 on (nginx 1.25.1 and later) in
// effect for the server, its own or else the http block's. found is false
// when there is no nginx.conf. unread names the files that could not be
// read: any of them may turn HTTP/2 on.
func NginxHTTP2(src Source) (on, found bool, unread []string) {
	f := NginxFeaturesAt(src, NginxConf)
	return f.HTTP2, f.Found, f.Unread
}

// NginxFeatures is what of nginx's configuration the November 2026
// advisories turn on: HTTP/2 (CVE-2026-123007, CVE-2026-123633), TLS 1.3
// (CVE-2026-118899) and the mail proxy (CVE-2026-113425).
type NginxFeatures struct {
	Found bool // there is an nginx.conf
	HTTP2 bool // a server speaks HTTP/2
	// TLS13: a TLS server (listen ... ssl, or ssl on) whose ssl_protocols,
	// its own or else the http block's, names TLSv1.3. TLSDefault: a TLS
	// server with no ssl_protocols in effect, which speaks TLS 1.3 from
	// nginx 1.23.4 on (nginx's default before it leaves TLS 1.3 out).
	TLS13, TLSDefault bool
	Mail              bool     // a mail block with a server: the mail proxy listens
	Unread            []string // files not read: any of them may turn one of these on
}

// NginxConf is nginx's configuration; OpenRestyConf is OpenResty's, under
// its own prefix.
const (
	NginxConf     = "/etc/nginx/nginx.conf"
	OpenRestyConf = "/usr/local/openresty/nginx/conf/nginx.conf"
)

// NginxHTTP2At is NginxHTTP2 for the configuration at conf (NginxConf or
// OpenRestyConf): its relative includes are under its own directory, and
// only files under that prefix are read.
func NginxHTTP2At(src Source, conf string) (on, found bool, unread []string) {
	f := NginxFeaturesAt(src, conf)
	return f.HTTP2, f.Found, f.Unread
}

// NginxFeaturesAt reads the configuration at conf as NginxHTTP2At does and
// reports the features the advisories need.
func NginxFeaturesAt(src Source, conf string) NginxFeatures {
	if !exists(src, conf) {
		return NginxFeatures{}
	}
	wc, dir := logConf, ""
	if conf != NginxConf {
		wc, dir = WebConf{Root: path.Dir(path.Dir(conf)), Owner: logConf.Owner}, path.Dir(conf)
	}
	l := &logLoader{src: src, conf: wc, out: map[string]*LogSource{}, ngxDir: dir}
	main := l.ngxFile(conf, 0)
	// A file read through a link (a linked directory on the way to it) or
	// from a package directory is judged as WebLogs judges it: its real path
	// under the root, it and every directory above it root's and not
	// writable by others. One that fails is not one only root controls: what
	// it says may hide HTTP/2, so it counts as not read.
	web := l.webAccounts()
	for _, p := range l.extraRead {
		if why := confTrusted(src, p, wc, web); why != "" {
			l.unread = append(l.unread, p+" ("+why+")")
		}
	}
	f := NginxFeatures{Found: true}
	ngxWalk(main, 0, func(d *ngxDir) {
		switch {
		case d.name == ngxTooDeep:
			l.unread = append(l.unread, "configuration nested deeper than 64 levels")
		case d.name == "http" && d.hasBlock:
			f.HTTP2 = f.HTTP2 || ngxHTTP2(d.block)
			tls13, def := ngxTLS13(d.block)
			f.TLS13, f.TLSDefault = f.TLS13 || tls13, f.TLSDefault || def
		case d.name == "mail" && d.hasBlock:
			for _, s := range d.block {
				f.Mail = f.Mail || s.name == "server" && s.hasBlock
			}
		}
	})
	f.Unread = l.unread
	return f
}

// ngxTLS13 reports whether a TLS server of an http block names TLSv1.3 in
// the ssl_protocols in effect for it (on), or has none in effect (def).
func ngxTLS13(http []*ngxDir) (on, def bool) {
	var protos []string // the http block's, inherited by its servers
	set, ssl := false, false
	for _, d := range http {
		switch {
		case d.name == "ssl_protocols":
			protos, set = d.args, true // the last one counts, as for http2
		case d.name == "ssl" && len(d.args) == 1:
			ssl = d.args[0] == "on"
		}
	}
	for _, s := range http {
		if s.name != "server" || !s.hasBlock {
			continue
		}
		p, pset, sslOn, listen := protos, set, ssl, false
		for _, d := range s.block {
			switch {
			case d.name == "ssl_protocols":
				p, pset = d.args, true
			case d.name == "ssl" && len(d.args) == 1:
				sslOn = d.args[0] == "on"
			case d.name == "listen" && contains(d.args, "ssl"):
				listen = true // TLS whatever ssl says, as listen ... http2 is HTTP/2
			}
		}
		switch {
		case !sslOn && !listen:
		case !pset:
			def = true
		case slices.ContainsFunc(p, func(v string) bool { return strings.EqualFold(v, "TLSv1.3") }): // nginx reads it in any case
			on = true
		}
	}
	return on, def
}

// ngxHTTP2 reports whether a server of an http block speaks HTTP/2.
func ngxHTTP2(http []*ngxDir) bool {
	inherit := false
	for _, d := range http {
		if d.name == "http2" && len(d.args) == 1 {
			inherit = d.args[0] == "on" // the last one counts, as nginx reports a duplicate
		}
	}
	for _, s := range http {
		if s.name != "server" || !s.hasBlock {
			continue
		}
		h2 := inherit
		for _, d := range s.block {
			switch {
			case d.name == "http2" && len(d.args) == 1:
				h2 = d.args[0] == "on"
			case d.name == "listen" && contains(d.args, "http2"):
				return true // listen ... http2 turns it on whatever http2 says
			}
		}
		if h2 {
			return true
		}
	}
	return false
}
