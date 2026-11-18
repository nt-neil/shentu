package hostenv

// NginxHTTP2 reads nginx's configuration as WebLogs does (/etc/nginx/nginx.conf
// and what it includes) and reports whether a server of it speaks HTTP/2: a
// listen with the http2 parameter, or http2 on (nginx 1.25.1 and later) in
// effect for the server, its own or else the http block's. found is false
// when there is no nginx.conf. unread names the files that could not be
// read: any of them may turn HTTP/2 on.
func NginxHTTP2(src Source) (on, found bool, unread []string) {
	const conf = "/etc/nginx/nginx.conf"
	if !exists(src, conf) {
		return false, false, nil
	}
	l := &logLoader{src: src, conf: logConf, out: map[string]*LogSource{}}
	main := l.ngxFile(conf, 0)
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
