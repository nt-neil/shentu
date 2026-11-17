package engine

import (
	"slices"
	"strings"
)

// A host allowlist checked before a request is a guard for the SSRF rules:
//
//	const u = new URL(req.query.target);
//	if (!ALLOWED.has(u.hostname)) return res.sendStatus(403);
//	await fetch(u);  // or fetch(req.query.target)
//
// The check validates u.hostname; where it holds, the request can only go to
// an allowed host, so u, and the string it was parsed from, are no longer
// the attack. The state records which variable holds a URL parsed from which
// value (urlKey+x+"\x00"+y) or the host of one (urlKey+"host:"+x+"\x00"+y),
// with urlKey itself set once there is any, so a new value of x or of y drops
// what it knew. Only the SSRF rules read it: a URL whose host is allowed may
// still carry a script or a quote in its path.
const urlKey = "\x00url:"

// urlParses: the calls whose result is the URL their first argument holds,
// and the members of that result that are its host.
var urlParses = map[string]struct {
	calls []string
	hosts []string // keys under the parsed value: its host
}{
	"js":     {[]string{"new URL(", "URL.parse(", "url.parse(", "new url.URL("}, []string{".hostname", ".host", ".origin"}},
	"python": {[]string{"urlparse(", "urlsplit(", "urllib.parse.urlparse(", "urllib.parse.urlsplit(", "parse.urlparse(", "parse.urlsplit("}, []string{".hostname", ".netloc"}},
	"php":    {[]string{"parse_url("}, []string{"[host]"}},
}

// parsedURL returns the key of the value t parses as a URL (new URL(x),
// urlparse(x), parse_url($x)), and whether t is its host itself
// (new URL(x).hostname, parse_url($x, PHP_URL_HOST)).
func (a *analysis) parsedURL(t []Token) (string, bool) {
	t = stripParens(t)
	p, ok := urlParses[a.lang()]
	if !ok || len(t) < 3 {
		return "", false
	}
	for _, c := range p.calls {
		cs := strings.Fields(strings.NewReplacer(".", " . ", "(", " (").Replace(c))
		if len(t) < len(cs)+1 {
			continue
		}
		match := true
		for i, w := range cs {
			if t[i].Text != w {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		open := len(cs) - 1
		end := closeOf(t, open)
		if end >= len(t) {
			continue
		}
		args := splitTop(inside(t, open, end), isComma)
		if len(args) == 0 {
			continue
		}
		y, _, ok := a.pathKey(stripParens(args[0]))
		if !ok {
			continue
		}
		rest := t[end+1:]
		switch {
		case len(rest) == 0 && a.php:
			// parse_url($x, PHP_URL_HOST) is the host; parse_url($x) an array
			return y, len(args) > 1 && len(args[1]) == 1 && args[1][0].Text == "PHP_URL_HOST"
		case len(rest) == 0:
			return y, false
		case len(rest) == 2 && memberOp(a.php, rest[0]) && slices.Contains(p.hosts, "."+rest[1].Text):
			return y, true // new URL(x).hostname
		}
	}
	return "", false
}

// setURLOf records, for an assignment key = rhs, that key holds a URL parsed
// from a value or that value's host, and forgets what it knew of key, and of
// the values parsed from it, before.
func (a *analysis) setURLOf(st state, key string, rhs []Token, plain bool) {
	if a.r.rule.Class != "ssrf" {
		return
	}
	if _, any := st[urlKey]; any && a.b.charge(len(st)) {
		for k := range st {
			x, ok := strings.CutPrefix(k, urlKey)
			if !ok || x == "" {
				continue
			}
			x = strings.TrimPrefix(x, "host:")
			to, from, _ := strings.Cut(x, "\x00")
			if to == key || strings.HasPrefix(to, key+sepCh) || from == key || strings.HasPrefix(from, key+sepCh) {
				delete(st, k)
			}
		}
	}
	if !plain {
		return
	}
	if y, host := a.parsedURL(rhs); y != "" && y != key {
		kind := ""
		if host {
			kind = "host:"
		}
		st[urlKey] = entry{san: true}
		st[urlKey+kind+key+"\x00"+y] = entry{san: true}
	}
}

// urlChecked adds, to the values a check validates, what an allowed host
// tells for the SSRF rules: a URL whose host it is, and the value that URL,
// or that host, was parsed from.
func (a *analysis) urlChecked(st state, keys []keyRef) []keyRef {
	if len(keys) == 0 || a.r.rule.Class != "ssrf" {
		return keys
	}
	if _, any := st[urlKey]; !any || !a.b.charge(len(st)) {
		return keys
	}
	hosts := urlParses[a.lang()].hosts
	seen := map[string]bool{}
	for _, k := range keys {
		seen[k.key] = true
	}
	add := func(k string, src bool) {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, keyRef{key: k, src: src})
		}
	}
	from := func(prefix string, src bool) {
		var ys []string
		for k := range st {
			if y, ok := strings.CutPrefix(k, prefix); ok {
				ys = append(ys, y)
			}
		}
		slices.Sort(ys)
		for _, y := range ys {
			add(y, src)
		}
	}
	for _, k := range slices.Clone(keys) {
		from(urlKey+"host:"+k.key+"\x00", k.src) // host = new URL(x).hostname: x
		for _, h := range hosts {
			h = strings.Replace(h, ".", sepCh+".", 1)
			h = strings.Replace(h, "[", sepCh+"[", 1)
			if u, ok := strings.CutSuffix(k.key, h); ok {
				if _, parsed := st[urlKey]; parsed {
					n := len(keys)
					from(urlKey+u+"\x00", k.src) // u = new URL(x); u.hostname: x
					if len(keys) > n {
						add(u, k.src) // and u itself
					}
				}
			}
		}
	}
	return keys
}
