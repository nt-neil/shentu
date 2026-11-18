package hostenv

import "path"

// NginxHTTP2 reads nginx's configuration as WebLogs does (/etc/nginx/nginx.conf
// and what it includes) and reports whether a server of it speaks HTTP/2: a
// listen with the http2 parameter, or http2 on (nginx 1.25.1 and later) in
// effect for the server, its own or else the http block's. found is false
// when there is no nginx.conf. unread names the files that could not be
// read: any of them may turn HTTP/2 on.
func NginxHTTP2(src Source) (on, found bool, unread []string) {
	return NginxHTTP2At(src, NginxConf)
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
	if !exists(src, conf) {
		return false, false, nil
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
	ngxWalk(main, 0, func(d *ngxDir) {
		switch {
		case d.name == ngxTooDeep:
			l.unread = append(l.unread, "configuration nested deeper than 64 levels")
		case d.name == "http" && d.hasBlock && ngxHTTP2(d.block):
			on = true
		}
	})
	return on, true, l.unread
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
