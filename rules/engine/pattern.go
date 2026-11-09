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
	raw    string
	php    bool
	toks   []Token
	member bool           // starts with ".", "->" or "?->": a method on any receiver
	text   *regexp.Regexp // text patterns only
	name   string         // last name in the pattern (to recognise prefix checks)
}

func compilePattern(lang, raw string, text bool) (*pat, error) {
	p := &pat{raw: raw, php: lang == "php"}
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
func (p *pat) at(toks []Token, i int, strict bool) bool {
	if p.text != nil || i+len(p.toks) > len(toks) {
		return false
	}
	for k, pt := range p.toks {
		if !tokEq(pt, toks[i+k]) {
			return false
		}
	}
	return !strict || p.member || i == 0 || !memberOp(p.php, toks[i-1])
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
