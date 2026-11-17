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
// allowlist that is surely a collection (.has(, .includes(, in; see
// collection) or a host written out (=== 'a.example') counts, and only the SSRF rules read it: a URL whose host is allowed may
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

// urlAlias+x+"\x01"+y records that x and y hold the same URL object (w = u):
// a write into one changes the other. Kept where either path has it.
const urlAlias = "\x00urlalias:"

// setURLOf records, for an assignment key = rhs, whether key holds a URL a
// parser made, forgetting what it knew of key and of what is under it. After
// w = u, w is that URL too and an alias of u.
func (a *analysis) setURLOf(st state, key string, rhs []Token, plain bool) {
	if a.r.rule.Class != "ssrf" {
		return
	}
	if _, ok := urlParses[a.lang()]; !ok {
		return
	}
	delete(st, urlKey+key)
	if !plain {
		return
	}
	if a.isURLParse(rhs) {
		st[urlKey+key] = entry{san: true}
	} else if rk, _, ok := a.pathKey(stripParens(rhs)); ok && rk != key {
		if _, parsed := st[urlKey+rk]; parsed {
			st[urlKey+key] = entry{san: true}
			// x = w after w = u: x is an alias of u too, so a write through
			// any of them ends every check
			for _, y := range append(aliasesOf(st, rk), rk) {
				if y != key {
					st[urlAlias+key+"\x01"+y], st[urlAlias+y+"\x01"+key] = entry{san: true}, entry{san: true}
				}
			}
		}
	}
}

// urlWrite: a write into a member of a parsed URL (u.host = v, u.href = v,
// Object.assign(u, {host: v}), or w.host = v after w = u) makes it another URL:
// what a check of its host said ends, and v's input is now in it.
func (a *analysis) urlWrite(st state, key string, v val) {
	if a.r.rule.Class != "ssrf" {
		return
	}
	for k := key; ; {
		i := strings.LastIndex(k, sepCh)
		if i < 0 {
			return
		}
		k = k[:i]
		if _, parsed := st[urlKey+k]; parsed {
			roots := append(aliasesOf(st, k), k)
			for _, r := range roots {
				delete(st, urlKey+r)
				if v.taint {
					e := st[r]
					e.taint, e.raw = true, e.raw || v.raw
					st[r] = e
				}
			}
			return
		}
	}
}

// aliasesOf lists the names that hold the same URL object as k.
func aliasesOf(st state, k string) []string {
	var out []string
	for x := range st {
		if y, ok := strings.CutPrefix(x, urlAlias+k+"\x01"); ok {
			out = append(out, y)
		}
	}
	return out
}

// urlAssignStmt is urlWrite for Object.assign(u, {...}): each later argument
// is written into u.
func (a *analysis) urlAssignStmt(st state, t []Token) {
	if a.r.rule.Class != "ssrf" || !a.js || len(t) < 5 || !t[0].word("Object") || !t[1].op(".") || !t[2].word("assign") || !t[3].op("(") ||
		closeOf(t, 3) != len(t)-1 && !(closeOf(t, 3) == len(t)-2 && t[len(t)-1].op(";")) {
		return
	}
	args := splitTop(inside(t, 3, closeOf(t, 3)), isComma)
	if len(args) < 2 {
		return
	}
	key, _, ok := a.pathKey(stripParens(args[0]))
	if !ok {
		return
	}
	var v val
	for _, x := range args[1:] {
		v = or(v, a.expr(st, x, false))
	}
	a.urlWrite(st, key+sepCh+".*", v)
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
			return a.collection(atom[:open-2])
		}
	}
	if a.py {
		if i := indexTop(atom, 0, isWord("in")); i > 0 {
			return a.collection(atom[i+1:])
		}
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

// collection reports whether t is surely a collection, so that .includes( and
// in test membership, not a substring: a list, array, tuple or set written
// out, new Set(...), set(...), the result of .split(...), or a name the file
// assigns only such values. A string, an environment value, or a name the file
// does not assign (imported, a parameter) may be a string.
func (a *analysis) collection(t []Token) bool {
	return a.collectionIn(t, 0, map[string]bool{})
}

// collectionIn is collection a few names deep, each name looked at once and
// through at most 8 of its definitions.
func (a *analysis) collectionIn(t []Token, depth int, seen map[string]bool) bool {
	t = stripParens(t)
	n := len(t)
	if n == 0 || depth > 4 {
		return false
	}
	if (t[0].op("[") || t[0].op("{") && a.py) && closeOf(t, 0) == n-1 {
		return true
	}
	if a.py && t[0].op("(") && closeOf(t, 0) == n-1 && indexTop(t[1:n-1], 0, isComma) >= 0 {
		return true // a tuple
	}
	if t[n-1].op(")") {
		open := openOf(t, n-1)
		switch {
		case open >= 2 && memberOp(a.php, t[open-2]) && t[open-1].word("split"):
			return true
		case !a.py && open == 2 && t[0].word("new") && (t[1].word("Set") || t[1].word("Map")):
			return true
		case !a.py && open == 3 && t[0].word("Object") && t[1].op(".") && (t[2].word("keys") || t[2].word("values")):
			return true
		case a.py && open == 1 && (t[0].word("set") || t[0].word("frozenset") || t[0].word("list") || t[0].word("tuple")):
			return true
		}
		return false
	}
	if n != 1 || t[0].Kind != Ident {
		return false
	}
	if seen[t[0].Text] {
		return false
	}
	seen[t[0].Text] = true
	if a.rdefs == nil {
		a.rdefs = recvDefs(a.ftoks)
	}
	ds := a.rdefs[t[0].Text]
	if len(ds) == 0 || len(ds) > 8 {
		return false
	}
	for _, d := range ds {
		if !a.collectionIn(d, depth+1, seen) {
			return false
		}
	}
	return true
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
