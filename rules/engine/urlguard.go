package engine

import (
	"slices"
	"strings"
)

// A host allowlist checked on a parsed URL before the request is a guard for
// the SSRF rules, for that URL object:
//
//	const u = new URL(req.query.target);
//	if (!ALLOWED.has(u.hostname)) return res.sendStatus(403);
//	await fetch(u);
//
// Where the check holds, u can only point at an allowed host. Only the parsed
// object is validated, not the string it was parsed from: another parser (a
// client's, url.parse, parse_url) may read the same string as another host.
// The state records which variable holds a URL a parser made (urlKey+x); a new
// value of x ends it, and so does a path on which x is something else (merge
// keeps it only where both paths have it). Only the check of a host against an
// allowlist (.has(, .includes(, in) or a host written out (=== 'a.example')
// counts, and only the SSRF rules read it: a URL whose host is allowed may
// still carry a script or a quote in its path.
const urlKey = "\x00url:"

// urlParses: the calls whose result is a URL object, and the members of it
// that are its host. JavaScript's WHATWG URL (what fetch reads), Python's
// urlparse and urlsplit, whose result a request is then built from
// (u.geturl(), urlunparse(u)).
var urlParses = map[string]struct {
	calls [][]string
	hosts []string
}{
	"js":     {[][]string{{"new", "URL", "("}, {"URL", ".", "parse", "("}, {"new", "url", ".", "URL", "("}}, []string{".hostname", ".host", ".origin"}},
	"python": {[][]string{{"urlparse", "("}, {"urlsplit", "("}, {"urllib", ".", "parse", ".", "urlparse", "("}, {"urllib", ".", "parse", ".", "urlsplit", "("}, {"parse", ".", "urlparse", "("}, {"parse", ".", "urlsplit", "("}}, []string{".hostname", ".netloc"}},
}

// isURLParse reports whether t is a call that makes a URL object, and
// nothing after it: new URL(x), urlparse(x).
func (a *analysis) isURLParse(t []Token) bool {
	t = stripParens(t)
	for _, c := range urlParses[a.lang()].calls {
		if len(t) <= len(c) {
			continue
		}
		match := true
		for i, w := range c {
			if t[i].Text != w {
				match = false
				break
			}
		}
		if match && closeOf(t, len(c)-1) == len(t)-1 {
			return true
		}
	}
	return false
}

// setURLOf records, for an assignment key = rhs, whether key holds a URL a
// parser made, forgetting what it knew of key and of what is under it.
func (a *analysis) setURLOf(st state, key string, rhs []Token, plain bool) {
	if a.r.rule.Class != "ssrf" {
		return
	}
	if _, ok := urlParses[a.lang()]; !ok {
		return
	}
	delete(st, urlKey+key)
	if plain && a.isURLParse(rhs) {
		st[urlKey+key] = entry{san: true}
	}
}

// hostCheck reports whether a condition atom checks a value against an
// allowlist or a host written out: ALLOWED.has(x), ALLOWED.includes(x),
// x in ALLOWED, x === 'a.example' (any negation of them). A truth test, a
// pattern or a prefix check does not say the host is an allowed one.
func (a *analysis) hostCheck(atom []Token) bool {
	atom = stripParens(atom)
	for len(atom) > 0 && (atom[0].op("!") || a.py && atom[0].word("not")) {
		atom = stripParens(atom[1:])
	}
	n := len(atom)
	if n > 3 && atom[n-1].op(")") {
		open := openOf(atom, n-1)
		if open >= 2 && memberOp(false, atom[open-2]) && (atom[open-1].word("has") || atom[open-1].word("includes")) {
			return true
		}
	}
	if a.py && indexTop(atom, 0, isWord("in")) > 0 {
		return true
	}
	for _, op := range []string{"===", "==", "!==", "!="} {
		if i := indexTop(atom, 0, isOp(op)); i > 0 {
			for _, side := range [][]Token{atom[:i], atom[i+1:]} {
				if side = stripParens(side); len(side) == 1 && side[0].Kind == Str && len(side[0].Parts) == 0 && side[0].Text != "" {
					return true
				}
			}
		}
	}
	return false
}

// urlChecked adds, to the values an allowlist check of a host validates, the
// URL object that is the host of, for the SSRF rules.
func (a *analysis) urlChecked(st state, atom []Token, keys []keyRef) []keyRef {
	if len(keys) == 0 || a.r.rule.Class != "ssrf" {
		return keys
	}
	p, ok := urlParses[a.lang()]
	if !ok || !a.hostCheck(atom) {
		return keys
	}
	for _, k := range slices.Clone(keys) {
		for _, h := range p.hosts {
			u, ok := strings.CutSuffix(k.key, sepCh+h)
			if !ok {
				continue
			}
			if e, parsed := st[urlKey+u]; parsed && e.san && !slices.ContainsFunc(keys, func(x keyRef) bool { return x.key == u }) {
				keys = append(keys, keyRef{key: u, src: k.src})
			}
		}
	}
	return keys
}
