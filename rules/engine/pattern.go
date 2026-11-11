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
	member   bool           // starts with ".", "->" or "?->": a method on any receiver
	anchored bool           // written with a leading "^": never a member of something else, even as a source
	text     *regexp.Regexp // text patterns only
	name     string         // last name in the pattern (to recognise prefix checks)
	chain    string         // PHP: "->m(" made from the sink "Class::m(": the chain must start at Class:: (chain.go)
	wild     bool           // holds "[*]", which matches any one index: $_FILES[*]['name']
	// sources only (source_args): the call is input only when its srcArg-th
	// argument is a string literal among srcVals (lower case)
	srcArg  int
	srcVals map[string]bool
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
	p.toks = toks
	for k := 0; k+2 < len(toks); k++ {
		if toks[k].op("[") && toks[k+1].op("*") && toks[k+2].op("]") {
			p.wild = true
		}
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
		if j >= len(toks) || !tokEq(p.toks[k], toks[j]) {
			return 0, false
		}
		j++
	}
	if p.chain != "" && !chainFrom(toks, i, p.chain) {
		return 0, false
	}
	if !strict || p.member || i == 0 || !memberOp(p.php, toks[i-1]) {
		return j, true
	}
	// readFileSync( also matches fs.readFileSync( when fs is a core module
	// (FlagModule, set by normalizeModules), never re.exec( on any object.
	return j, !p.php && i >= 2 && toks[i-1].op(".") && toks[i-2].Flags&FlagModule != 0 && (i == 2 || !memberOp(false, toks[i-3]))
}

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
