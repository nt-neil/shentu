package engine

import (
	"slices"
	"strings"
)

// realKey marks, in a state, that a PHP variable holds realpath(x) of a plain
// path x: realKey+real+"\x00"+x, with realKey+real itself set, so a new value of
// real can drop what it knew. realpath() resolves x as a file call would, so a
// check on the real path says the same of x: under a base directory, x opens a
// file there; found at all (not false), x is a local path, never a URL or a
// stream wrapper, which realpath() does not open.
const realKey = "\x00real:"

var realpathPat = func() *pat {
	p, err := compilePattern("php", "realpath(", false)
	if err != nil {
		panic(err)
	}
	return p
}()

// setRealOf records, after key = rhs, which path key is the real path of. Any
// assignment forgets the real paths of the value it changes ($p = ... after
// $real = realpath($p) leaves $real about the old $p). realKey alone marks a
// state that holds any, so a state without one costs no walk.
func (a *analysis) setRealOf(st state, key string, rhs []Token, plain bool) {
	if _, any := st[realKey]; any && a.b.charge(len(st)) {
		for k := range st {
			x, ok := strings.CutPrefix(k, realKey)
			if !ok {
				continue
			}
			real, of, two := strings.Cut(x, "\x00")
			if real == key || two && (of == key || strings.HasPrefix(of, key+sepCh)) {
				delete(st, k)
			}
		}
	}
	if !plain {
		return
	}
	t := stripParens(rhs)
	for len(t) > 0 && t[0].op("@") {
		t = t[1:]
	}
	m, n := len(realpathPat.toks), len(t)
	if m >= n || !realpathPat.at(t, 0, true) || closeOf(t, m-1) != n-1 {
		return
	}
	args := splitTop(t[m:n-1], isComma)
	if len(args) != 1 {
		return
	}
	x, _, ok := a.pathKey(stripParens(args[0]))
	if !ok || x == key {
		return // realpath($p) . '/x' or $p = realpath($p): no longer x itself
	}
	st[realKey], st[realKey+key] = entry{san: true}, entry{san: true}
	st[realKey+key+"\x00"+x] = entry{san: true}
}

// realOrigins adds to keys the paths the checked values are the real paths
// of: a check of $real = realpath($p) checks $p.
func (a *analysis) realOrigins(st state, keys []keyRef) []keyRef {
	if _, any := st[realKey]; !any || len(keys) == 0 || !a.b.charge(len(st)) {
		return keys
	}
	var add []keyRef
	for _, k := range keys {
		pre := realKey + k.key + "\x00"
		for s := range st {
			if x, ok := strings.CutPrefix(s, pre); ok {
				add = append(add, keyRef{key: x})
			}
		}
	}
	slices.SortFunc(add, func(x, y keyRef) int { return strings.Compare(x.key, y.key) })
	return append(keys, add...)
}

// realFound reads a check that realpath() found the file ($real === false,
// !$real, $real !== false) in the rules that take realpath() as a sanitizer
// (a server-side request, a phar:// read): where it found one, the path it
// was given is a local file. keys are those paths, pos whether the atom is
// true when realpath() found it.
func (a *analysis) realFound(st state, atom []Token) (pos bool, keys []keyRef) {
	if !a.php || !a.realpathCleans() {
		return false, nil
	}
	if _, any := st[realKey]; !any {
		return false, nil
	}
	pos = true
	atom = stripParens(atom)
	for len(atom) > 0 && atom[0].op("!") {
		pos, atom = !pos, stripParens(atom[1:])
	}
	if i := indexTop(atom, 0, a.isCompare); i > 0 {
		lhs, op, rhs := atom[:i], atom[i].Text, atom[i+1:]
		if isLiteral(lhs) {
			lhs, rhs = rhs, lhs
		}
		if len(rhs) != 1 || !rhs[0].word("false") || op != "===" && op != "!==" {
			return false, nil // == false also holds for "" and "0", which realpath() never gives, but keep to the strict test
		}
		if op == "===" {
			pos = !pos
		}
		atom = stripParens(lhs)
	}
	key, _, ok := a.pathKey(atom)
	if !ok {
		return false, nil
	}
	if _, found := st[realKey+key]; !found {
		return false, nil
	}
	return pos, a.realOrigins(st, []keyRef{{key: key}})[1:]
}

// realpathCleans reports whether the rule lists realpath() as a sanitizer.
func (a *analysis) realpathCleans() bool {
	for _, s := range a.r.sanitizers {
		if len(s.toks) > 0 && s.toks[0].word("realpath") {
			return true
		}
	}
	return false
}

// guardedParams adds to set, at a return that can be true, the parameters that
// were given input and hold none there although the body never assigns,
// references or unsets them: a check on the way cleaned them
// (if (!in_base($real)) { return false; } ... return true;), so a true result
// says the argument passed it, as return in_array($p, ...) does.
func (a *analysis) guardedParams(st state, set map[string]bool) {
	for _, p := range a.curParams {
		if p == "" || !a.curGiven[p] || a.curMoved[p] || a.curUnset[p] || set[p] {
			continue
		}
		if e, ok := st.get(p); ok && e.taint {
			continue
		}
		set[p] = true
	}
}

// unsetParams are the parameters a body hands to unset(): no longer what the
// caller passed, as an assigned one is not (paramsMoved).
func unsetParams(body []*stmt, params []string) map[string]bool {
	var out map[string]bool
	walkToks(body, 0, func(t []Token) {
		for i := 0; i+1 < len(t); i++ {
			if !t[i].word("unset") || !t[i+1].op("(") {
				continue
			}
			end := closeOf(t, i+1)
			if end < 0 {
				end = len(t) - 1
			}
			for _, v := range t[i+2 : end] {
				if v.Kind == Var && slices.Contains(params, v.Text) {
					if out == nil {
						out = map[string]bool{}
					}
					out[v.Text] = true
				}
			}
		}
	})
	return out
}

// callAtom reports whether a condition atom tests a call's result (a check:
// strpos($real, $base) === 0, in_array($real, $files, true)), not a value
// itself ($real, $real === false), with any ! and comparison taken off.
func (a *analysis) callAtom(atom []Token) bool {
	atom = stripParens(atom)
	for len(atom) > 0 && (atom[0].op("!") || a.py && atom[0].word("not")) {
		atom = stripParens(atom[1:])
	}
	if i := indexTop(atom, 0, a.isCompare); i > 0 {
		lhs, rhs := atom[:i], atom[i+1:]
		if isLiteral(lhs) {
			lhs = rhs
		}
		atom = stripParens(lhs)
	}
	if _, _, ok := a.pathKey(atom); ok || len(atom) < 3 {
		return false
	}
	return atom[len(atom)-1].op(")")
}

// lossy are the calls that drop part of a value: a lookup of their result
// says nothing of the value inside (in_array(basename($p), $files) holds for
// ../../x/log.txt, in_array(intval($x), $ids) for "1 OR 1"). Other calls keep
// what they said before: in_array(strtolower($o), ...) leaves $o one of the
// list in another case, and in_array(parse_url($u, PHP_URL_HOST), $hosts)
// checks the host of $u.
var lossy = map[string]bool{"basename": true, "pathinfo": true, "dirname": true, "intval": true, "floatval": true,
	"absint": true, "abs": true, "sanitize_file_name": true, "sanitize_key": true, "sanitize_title": true}

// lossyLookup reports a lookup subject that is one of the lossy calls.
func lossyLookup(arg []Token) bool {
	arg = stripParens(arg)
	n := len(arg)
	if n < 3 || arg[0].Kind != Ident || !arg[1].op("(") || closeOf(arg, 1) != n-1 {
		return false
	}
	return lossy[strings.ToLower(strings.TrimPrefix(arg[0].Text, "\\"))]
}
