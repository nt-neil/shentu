package engine

import (
	"fmt"
	"regexp"
	"strings"
)

// pat is a compiled source, sink, sanitizer or argument fragment. A code pattern
// is lexed with the rule's language and matched token by token, so it never
// matches inside comments or string literals. A text pattern (listed in the rule's
// `text`) is matched case-insensitively inside string literals instead.
type pat struct {
	raw      string
	php      bool
	toks     []Token
	member   bool            // starts with ".", "->" or "?->": a method on any receiver
	anchored bool            // written with a leading "^": never a member of something else, even as a source
	text     *regexp.Regexp  // text patterns only
	name     string          // last name in the pattern (to recognise prefix checks)
	chain    string          // PHP: "->m(" made from the sink "Class::m(": the chain must start at Class:: (chain.go)
	chainNot map[string]bool // calls the chain may not go through: they make another object (rule chain_not)
	chainVia string          // a call the chain must go through: httpx.Client(*).get( (chain.go viaSink)
	wild     bool            // holds "[*]", which matches any one index: $_FILES[*]['name']
	// memberWild: ends in "->*" (".*"): any one member read as a value, neither
	// called nor read further: $request->sort, not $request->user() or
	// $request->query->get(
	memberWild bool
	// sources only (source_args): the call (or index) is input only when its
	// srcArg-th argument is a string literal among srcVals (lower case; "*": any; "!x": not x;
	// "?": an argument that is not a string literal)
	srcArg  int
	srcVals map[string]bool
	// sources only: members the rule's route_not leaves out of a source that
	// ends in that member (sourcenot.go)
	notMembers []string
}

func compilePattern(lang, raw string, text bool) (*pat, error) {
	p := &pat{raw: raw, php: lang == "php"}
	if !text && strings.HasPrefix(raw, "^") {
		// "^request.url" matches request.url but not this.request.url.
		p.anchored, raw = true, raw[1:]
	}
	if text {
		words := strings.Fields(raw)
		if len(words) == 0 {
			return nil, fmt.Errorf("empty text pattern")
		}
		for i, w := range words {
			words[i] = regexp.QuoteMeta(w)
		}
		re := `(?i)` + strings.Join(words, `\s+`)
		if isIdentChar(raw[0]) {
			re = `(?i)\b` + re[4:]
		}
		if isIdentChar(raw[len(raw)-1]) {
			re += `\b`
		}
		p.text = regexp.MustCompile(re)
		return p, nil
	}
	var toks []Token
	switch lang {
	case "php":
		toks = lexPHP(raw, nil, true)
	case "python":
		for _, t := range lexPython(raw, nil) {
			if t.Kind != Newline && t.Kind != Indent && t.Kind != Dedent {
				toks = append(toks, t)
			}
		}
	case "js":
		toks = lexJS(raw, nil)
	default:
		return nil, fmt.Errorf("unknown language %q", lang)
	}
	if len(toks) == 0 {
		return nil, fmt.Errorf("pattern %q has no code tokens", raw)
	}
	for i := range toks {
		toks[i].Line, toks[i].Flags = 0, toks[i].Flags&^FlagNL
	}
	if p.php {
		for k := 0; k+1 < len(toks); k++ {
			if toks[k].Kind == Ident && toks[k+1].op("(") {
				toks[k].Flags |= FlagFold // function and method names: SYSTEM($x) runs system()
			}
		}
	}
	p.toks = toks
	for k := 0; k+2 < len(toks); k++ {
		if toks[k].op("[") && toks[k+1].op("*") && toks[k+2].op("]") {
			p.wild = true
		}
	}
	if n := len(toks); n >= 3 && toks[n-1].op("*") && memberOp(p.php, toks[n-2]) {
		p.memberWild = true
	}
	p.member = memberOp(p.php, toks[0]) && toks[0].Text != "::"
	for _, t := range toks {
		if t.Kind == Ident {
			p.name = t.Text
		}
	}
	return p, nil
}

// memberOp reports whether t accesses a member: "->", "?->" and "::" in PHP (where
// "." joins strings), "." and "?." in JavaScript and Python.
func memberOp(php bool, t Token) bool {
	if t.Kind != Op {
		return false
	}
	if php {
		return t.Text == "->" || t.Text == "?->" || t.Text == "::"
	}
	return t.Text == "." || t.Text == "?."
}

func tokEq(p, c Token) bool {
	if p.Kind != c.Kind {
		return false
	}
	if p.Kind == Str {
		if p.Flags&FlagShell != c.Flags&FlagShell || c.Flags&FlagRegex != 0 {
			return false
		}
		if p.Flags&FlagOpen != 0 {
			return strings.HasPrefix(c.Text, p.Text)
		}
	}
	if p.Flags&FlagFold != 0 {
		return strings.EqualFold(p.Text, c.Text)
	}
	return p.Text == c.Text
}

// at reports whether p matches toks at i. A strict match also requires that a
// pattern starting with a name is not a member of something else: "exec(" matches
// exec($x) but not $pdo->exec($x) or re.exec(s); write "->exec(" or ".exec(" for those.
// In JavaScript it is allowed as a member of a Node core module: fs.readFileSync(.
func (p *pat) at(toks []Token, i int, strict bool) bool {
	_, ok := p.match(toks, i, strict)
	return ok
}

// match is at that also returns where the match ends: a "[*]" in the pattern
// takes a whole index of the code, so the length can differ from the pattern's.
func (p *pat) match(toks []Token, i int, strict bool) (int, bool) {
	if p.text != nil || i+len(p.toks) > len(toks) {
		return 0, false
	}
	if p.anchored && i > 0 && memberOp(p.php, toks[i-1]) {
		return 0, false
	}
	j := i
	for k := 0; k < len(p.toks); k++ {
		if p.wild && k+2 < len(p.toks) && p.toks[k].op("[") && p.toks[k+1].op("*") && p.toks[k+2].op("]") {
			if j >= len(toks) || !toks[j].op("[") {
				return 0, false
			}
			j, k = closeOf(toks, j)+1, k+2
			continue
		}
		if p.memberWild && k == len(p.toks)-1 {
			if j >= len(toks) || toks[j].Kind != Ident || j+1 < len(toks) && (toks[j+1].op("(") || toks[j+1].op("[") || memberOp(p.php, toks[j+1]) || toks[j+1].op("?.")) {
				return 0, false
			}
			j++
			continue
		}
		if j >= len(toks) || !tokEq(p.toks[k], toks[j]) {
			return 0, false
		}
		j++
	}
	if p.chain != "" && !chainFrom(toks, i, p.chain, p.chainVia, p.chainNot) {
		return 0, false
	}
	if strict && p.php && i > 0 && len(p.toks) > 1 && p.toks[0].Kind == Ident && p.toks[1].op("(") &&
		phpFuncPattern(p.toks[0].Text) && phpNotGlobalCall(toks, i) {
		return 0, false
	}
	if !strict || p.member || i == 0 || !memberOp(p.php, toks[i-1]) {
		return j, true
	}
	// readFileSync( also matches fs.readFileSync( when fs is a core module
	// (FlagModule, set by normalizeModules), never re.exec( on any object.
	return j, !p.php && i >= 2 && toks[i-1].op(".") && toks[i-2].Flags&FlagModule != 0 && (i == 2 || !memberOp(false, toks[i-3]))
}

// phpFuncPattern reports whether a pattern name names a PHP function: written
// in lower case, as the rules write functions, and one PHP has. Key( names
// php-jwt's class Key, not key(), so new Key($secret) still matches it.
func phpFuncPattern(name string) bool {
	return name == strings.ToLower(name) && phpBuiltins[name]
}

// phpNotGlobalCall reports whether the name at toks[i], followed by "(", is
// no call of the PHP function a pattern like "file(" names: a class built with
// new (new File($p), new \File($p)), or a function of a namespace: a qualified
// name, A\file($p) or A\B\file($p), written as one word (FlagQualified), and
// namespace\file($p) in a file that declares a namespace. \file($p) after
// anything else (echo \system(, $a and \system(, x ?: \file() and file($p)
// inside a namespace are the PHP function. Only a pattern naming a PHP
// function is held to this: one naming a class, PDO( or mysqli(, is written
// for new PDO(...).
func phpNotGlobalCall(toks []Token, i int) bool {
	if phpWord(toks[i-1], "new") || toks[i-1].op(`\`) && i >= 2 && phpWord(toks[i-2], "new") {
		return true
	}
	if !toks[i-1].op(`\`) || toks[i-1].Flags&FlagQualified == 0 {
		return false
	}
	if i >= 2 && phpWord(toks[i-2], "namespace") {
		return declaresNamespace(toks) // with no namespace declared, namespace\ is the global one
	}
	// echo\system($c): PHP 8 reads one name, PHP 7 echo and \system(). Say the
	// call is PHP's whenever a reserved word comes right before the backslash.
	return i < 2 || !phpReserved[strings.ToLower(toks[i-2].Text)]
}

// phpReserved are PHP's reserved keywords (php.net, "List of Keywords").
var phpReserved = words("__halt_compiler abstract and array as break callable case catch class clone const continue " +
	"declare default die do echo else elseif empty enddeclare endfor endforeach endif endswitch endwhile enum eval exit " +
	"extends final finally fn for foreach function global goto if implements include include_once instanceof insteadof " +
	"interface isset list match namespace new or print private protected public readonly require require_once return " +
	"static switch throw trait try unset use var while xor yield from")

// declaresNamespace reports whether toks declare a named namespace
// (namespace App;) and no global one (namespace { ... }), so namespace\ can
// only be a named one. toks may be only part of the file; then it may say no
// for a file that declares one, and the call counts as PHP's, which reports.
func declaresNamespace(toks []Token) bool {
	named := false
	for k := 0; k+1 < len(toks); k++ {
		if !phpWord(toks[k], "namespace") {
			continue
		}
		switch {
		case toks[k+1].op("{"):
			return false // a global namespace block: namespace\ in it is the global one
		case toks[k+1].Kind == Ident:
			named = true
		}
	}
	return named
}

// phpWord reports whether t is the PHP keyword w, which PHP reads in any case
// (NEW, Namespace).
func phpWord(t Token, w string) bool { return t.Kind == Ident && strings.EqualFold(t.Text, w) }

// baseAt reports whether the part of an indexed source before its first index
// matches at i: $f = $_FILES['doc'] holds $_FILES[*]['name'] under 'name'
// (sourceParts), so the file holds the source although it never writes it out.
func (p *pat) baseAt(toks []Token, i int) bool {
	if p.text != nil || !p.toks[len(p.toks)-1].op("]") {
		return false
	}
	for k, pt := range p.toks {
		if pt.op("[") {
			return k > 0
		}
		if i+k >= len(toks) || !tokEq(pt, toks[i+k]) {
			return false
		}
	}
	return false
}

// rest returns what is left of the pattern after it matched all of toks, when
// that is a list of fixed indexes: for $_FILES[*]['name'] and $_FILES['doc'],
// ['name']. A variable holding $_FILES['doc'] then holds input under 'name'.
func (p *pat) rest(toks []Token) []Token {
	if p.text != nil || !p.toks[len(p.toks)-1].op("]") {
		return nil
	}
	j := 0
	for k := 0; k < len(p.toks); k++ {
		if j == len(toks) {
			r := p.toks[k:]
			for m := 0; m < len(r); m += 3 {
				if m+2 >= len(r) || !r[m].op("[") || r[m+1].Kind != Str || !r[m+2].op("]") {
					return nil
				}
			}
			return r
		}
		if p.wild && k+2 < len(p.toks) && p.toks[k].op("[") && p.toks[k+1].op("*") && p.toks[k+2].op("]") {
			if !toks[j].op("[") {
				return nil
			}
			j, k = closeOf(toks, j)+1, k+2
			continue
		}
		if !tokEq(p.toks[k], toks[j]) {
			return nil
		}
		j++
	}
	return nil
}

// within reports whether p occurs anywhere in toks (argument fragments).
func (p *pat) within(toks []Token) bool {
	for i := range toks {
		if p.at(toks, i, false) {
			return true
		}
	}
	return false
}

// callParen returns the offset in p of the "(" whose group is still open at the
// end of the pattern ("mail(" -> 4, "subprocess.run([" -> 3), or -1.
func (p *pat) callParen() int {
	var stack []int
	for k, t := range p.toks {
		switch {
		case isOpen(t):
			stack = append(stack, k)
		case isClose(t) && len(stack) > 0:
			stack = stack[:len(stack)-1]
		}
	}
	for k := len(stack) - 1; k >= 0; k-- {
		if p.toks[stack[k]].op("(") {
			return stack[k]
		}
	}
	return -1
}

// argOpen is where a source with source_args takes its arguments: the "(" of
// a call source, or the "[" a source ends with (req.headers[: the index is
// its one argument), else -1.
func (p *pat) argOpen() int {
	if k := p.callParen(); k >= 0 {
		return k
	}
	if n := len(p.toks); n > 0 && p.toks[n-1].op("[") {
		return n - 1
	}
	return -1
}
