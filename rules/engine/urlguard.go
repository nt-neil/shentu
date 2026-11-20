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

// maxURLAliases: a URL held by more names than this holds no check (the
// aliases of each are kept for each, so they cost their square).
const maxURLAliases = 64

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
	if rk, _, ok := a.pathKey(stripParens(rhs)); ok && rk == key && plain {
		return // u = u: the same object
	}
	delete(st, urlKey+key)
	if !plain {
		return
	}
	// only a plain name holds a checked URL, and only one no other function
	// of the file reaches (captured): a member (this.u, o.u) or a name a
	// closure uses may change where the analysis does not look
	own := func() bool { return !strings.Contains(key, sepCh) && !a.captured(key) }
	if a.isURLParse(rhs) {
		if own() {
			st[urlKey+key] = entry{san: true}
		}
	} else if rk, _, ok := a.pathKey(stripParens(rhs)); ok && rk != key {
		if e, parsed := st[urlKey+rk]; parsed {
			if als := aliasesOf(st, rk); len(als) >= maxURLAliases || !own() {
				// u went where it may change, or too many names hold it:
				// u, its aliases and key hold again what u held before a check
				a.urlChanged(st, rk, val{}, true)
				if x, ok := st[rk]; ok {
					st[key] = x
				}
				return
			}
			// and the input u held before a check, for urlChanged
			st[urlKey+key] = entry{san: true, taint: e.taint, raw: e.raw}
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
// or w.host = v after w = u) makes it another URL: what a check of its host
// said ends, and v's input is now in it.
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
			a.urlChanged(st, k, v, false)
			return
		}
	}
}

// urlChanged ends what a check said of the URL object u and of every name
// holding it, and puts v's input into them; with unknown (u went into a
// function that may change it), also the input u held before the check.
func (a *analysis) urlChanged(st state, u string, v val, unknown bool) {
	for _, r := range append(aliasesOf(st, u), u) {
		e, parsed := st[urlKey+r]
		delete(st, urlKey+r)
		if v.taint || unknown && parsed && e.taint {
			x := st[r]
			x.taint, x.raw = true, x.raw || v.raw || unknown && e.raw
			st[r] = x
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

// urlCallsStmt: a call in the statement that is given a parsed URL may
// change it. Object.assign(u, {host: v}) and Reflect.set(u, 'host', v) write
// the other arguments into u, anywhere in the statement (const z =
// Object.assign(u, ...)). In JavaScript any other call given u, except the
// rule's own sinks, may change it too (setHost(u, v)): the check of u ends and
// u holds again the input it held before it. Python's parse results cannot be
// changed in place. This reports more than it must: a call that only reads u
// (log(u)) ends the check as well.
func (a *analysis) urlCallsStmt(st state, t []Token) {
	if a.r.rule.Class != "ssrf" || !a.js {
		return
	}
	// a URL written into an object or array ({ target: u }, [u]) goes where
	// it may be changed through that literal
	// u used as a value in any other way than a member read (u.hostname, but
	// not u.valueOf(), which is u), a whole argument (handled below), the whole
	// right side (w = u: an alias) or the target (u = ...) may now be held by
	// another name (a1 = u || null, c ? u : w, return u), which the analysis
	// does not follow
	for i, tk := range t {
		if tk.Kind != Ident || i > 0 && (memberOp(false, t[i-1]) || t[i-1].op("?.")) {
			continue
		}
		if _, parsed := st[urlKey+tk.Text]; !parsed {
			continue
		}
		var prev, next Token
		if i > 0 {
			prev = t[i-1]
		}
		if i+1 < len(t) {
			next = t[i+1]
		}
		switch {
		case (next.op(".") || next.op("?.")) && i+3 < len(t) && t[i+2].word("valueOf") && t[i+3].op("("),
			next.op("[") && closeOf(t, i+1)+1 < len(t) && t[closeOf(t, i+1)+1].op("("):
			// u.valueOf() is u itself, not a member of it: held by another name;
			// so may be a method called by a computed name (u['valueOf']())
		case next.op(".") || next.op("?.") || next.op("["), // u.hostname, u['host']
			next.op("=") || next.op("+="), // u = ..., written by assign
			(prev.op("(") || prev.op(",")) && (next.op(")") || next.op(",")) && callArg(t, i), // f(u)
			prev.op("=") && i == len(t)-1 || prev.op("=") && next.op(";"):                     // w = u
			continue
		}
		a.urlChanged(st, tk.Text, val{}, true)
	}
	var lit []bool // per open bracket: an object or array written out
	in := 0        // how many of them hold the token
	for i, tk := range t {
		switch {
		case isOpen(tk):
			l := (tk.op("{") || tk.op("[")) && literalOpen(t, i)
			lit = append(lit, l)
			if l {
				in++
			}
		case isClose(tk) && len(lit) > 0:
			if lit[len(lit)-1] {
				in--
			}
			lit = lit[:len(lit)-1]
		case in > 0 && tk.Kind == Ident:
			if _, parsed := st[urlKey+tk.Text]; parsed {
				a.urlChanged(st, tk.Text, val{}, true)
			}
		}
	}
	for i := 1; i < len(t); i++ {
		if !t[i].op("(") || !(t[i-1].Kind == Ident || t[i-1].op(")")) {
			continue
		}
		args := splitTop(inside(t, i, closeOf(t, i)), isComma)
		start := a.chainStart(t, i)
		write := i-start == 3 && t[start+1].op(".") && (t[start].word("Object") && t[start+2].word("assign") || t[start].word("Reflect") && t[start+2].word("set"))
		if !write {
			sink := false
			for _, s := range a.r.sinks {
				sink = sink || s.at(t, start, false)
			}
			if sink {
				continue
			}
		}
		for k, arg := range args {
			key, _, ok := a.pathKey(stripParens(arg))
			if !ok {
				continue
			}
			if _, parsed := st[urlKey+key]; !parsed {
				continue
			}
			var v val
			for m, x := range args {
				if m != k {
					v = or(v, a.expr(st, x, false))
				}
			}
			a.urlChanged(st, key, v, !write)
		}
	}
}

// callArg reports whether t[i] is directly inside a call's parentheses.
func callArg(t []Token, i int) bool {
	depth := 0
	for j := i - 1; j >= 0; j-- {
		switch {
		case isClose(t[j]):
			depth++
		case isOpen(t[j]):
			if depth == 0 {
				return t[j].op("(") && j > 0 && (t[j-1].Kind == Ident || t[j-1].op(")"))
			}
			depth--
		}
	}
	return false
}

// literalOpen reports whether the { or [ at t[i] starts an object or array
// written out, not an index (a[i]) or a block (=> {).
func literalOpen(t []Token, i int) bool {
	if i == 0 {
		return true
	}
	p := t[i-1]
	if t[i].op("[") {
		return !(p.Kind == Ident && !p.word("return") && !p.word("in") && !p.word("of") || p.Kind == Str || p.op(")") || p.op("]") || p.op("?."))
	}
	return p.op("=") || p.op("(") || p.op(",") || p.op(":") || p.op("[") || p.op("?") || p.op("||") || p.op("&&") || p.op("??") || p.op("...") ||
		p.word("return") || p.word("yield") || p.word("await")
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
// in test membership, not a substring. Only the simplest cases count, and
// anything else may be a string (more findings, never fewer):
//   - a list, array, set or tuple written out, new Set(...), set(...),
//     frozenset(...), or a chain of member reads and calls ending in .split(...),
//     as the whole expression (no ||, or, ?: around it);
//   - a name the file binds once, at its top level, to one of those
//     (collectionName).
func (a *analysis) collection(t []Token) bool {
	if a.collectionValue(t) {
		return true
	}
	t = stripParens(t)
	return len(t) == 1 && t[0].Kind == Ident && a.collectionName(t[0].Text)
}

// collectionValue reports whether the whole of t makes a collection.
func (a *analysis) collectionValue(t []Token) bool {
	for len(t) >= 2 && t[0].op("(") && closeOf(t, 0) == len(t)-1 {
		if a.py && indexTop(t[1:len(t)-1], 0, isComma) >= 0 {
			return true // a tuple: ('a', 'b')
		}
		t = t[1 : len(t)-1]
	}
	n := len(t)
	if n == 0 {
		return false
	}
	if (t[0].op("[") || a.py && t[0].op("{")) && closeOf(t, 0) == n-1 {
		return true
	}
	if !t[n-1].op(")") {
		return false
	}
	open := openOf(t, n-1)
	switch {
	case !a.py && open == 2 && t[0].word("new") && t[1].word("Set"),
		a.py && open == 1 && (t[0].word("set") || t[0].word("frozenset")):
		// of a collection: new Set(process.env.H) is a set of characters
		arg := t[open+1 : n-1]
		return len(arg) > 0 && a.collection(arg)
	case open >= 3 && (t[open-2].op(".") || t[open-2].op("?.")) && t[open-1].word("split"):
		return postfixChain(t[:open-2])
	}
	return false
}

// postfixChain reports whether t is one value read through members, indexes
// and calls only (process.env.HOSTS, os.environ.get('H', 'a'), (x || y)), with
// no operator at its top.
func postfixChain(t []Token) bool {
	if len(t) == 0 {
		return false
	}
	i := 1
	switch {
	case t[0].op("("):
		i = closeOf(t, 0) + 1
	case t[0].Kind != Ident && t[0].Kind != Str:
		return false
	}
	for i < len(t) {
		switch {
		case (t[i].op(".") || t[i].op("?.")) && i+1 < len(t) && t[i+1].Kind == Ident:
			i += 2
		case t[i].op("(") || t[i].op("["):
			i = closeOf(t, i) + 1
		default:
			return false
		}
	}
	return i == len(t)
}

// collectionName reports whether the file binds name exactly once, with const
// (let, var) or a plain assignment at its top level, to a collection
// (collectionValue), and otherwise only reads it: name.has(...), name[i],
// Python's x in name. Any other occurrence (a parameter, destructuring, catch,
// for, with, a key name: in an object, a default value, +=, a tuple of
// targets, an argument) may bind or change it, so the name does not count.
func (a *analysis) collectionName(name string) bool {
	if v, ok := a.colls[name]; ok {
		return v
	}
	if a.colls == nil {
		a.colls = map[string]bool{}
	}
	a.colls[name] = false // while it is worked out: A = new Set(B), B = new Set(A)
	t := a.ftoks
	if a.py {
		for i := 1; i < len(t); i++ {
			if t[i].op("*") && t[i-1].word("import") {
				a.colls[name] = false // from x import * may bind any name
				return false
			}
		}
	}
	defs, ok := 0, true
	depth, indent := 0, 0
	for i := 0; i < len(t) && ok; i++ {
		tk := t[i]
		switch {
		case isOpen(tk):
			depth++
		case isClose(tk):
			depth--
		case tk.Kind == Indent:
			indent++
		case tk.Kind == Dedent:
			indent--
		}
		if tk.Kind != Ident || tk.Text != name || i > 0 && (memberOp(a.php, t[i-1]) || t[i-1].op("?.")) {
			continue
		}
		next := Token{}
		if i+1 < len(t) {
			next = t[i+1]
		}
		switch {
		case next.op("=") && depth == 0 && (a.py && indent == 0 && lineStart(t, i) ||
			!a.py && i > 0 && (t[i-1].word("const") || t[i-1].word("let") || t[i-1].word("var"))):
			defs++
			if defs > 1 || !a.collectionValue(stmtRest(t, i+2)) {
				ok = false
			}
		case next.op(".") || next.op("?.") || next.op("["):
			// a read: ALLOWED.has(h), ALLOWED[0]
		case a.py && i > 0 && t[i-1].word("in") && !(i > 1 && t[i-2].word("for")):
			// x in ALLOWED
		default:
			ok = false
		}
	}
	v := ok && defs == 1
	a.colls[name] = v
	return v
}

// stmtRest returns the expression starting at t[i] up to the end of its
// statement: a ";", a "," or a new line outside brackets.
func stmtRest(t []Token, i int) []Token {
	depth := 0
	for j := i; j < len(t); j++ {
		switch {
		case isOpen(t[j]):
			depth++
		case isClose(t[j]):
			if depth == 0 {
				return t[i:j]
			}
			depth--
		case depth == 0 && (t[j].op(";") || t[j].op(",") || t[j].Kind == Newline || j > i && t[j].Line != t[j-1].Line):
			return t[i:j]
		}
	}
	return t[i:]
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
				// remember the input u held before the check, for a call that may change it (urlCallsStmt)
				if x, _ := st.get(u); x.taint {
					e.taint, e.raw = true, x.raw
					st[urlKey+u] = e
				}
			}
		}
	}
	return keys
}
