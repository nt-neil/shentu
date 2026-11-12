package engine

import "strings"

// regexCheck recognises a regular-expression test used as a condition that
// restricts a value to letters, digits, "_" and "-":
//
//	preg_match('/^[a-z0-9_]+$/i', $x)   re.fullmatch(r'[\w-]+', x)   /^\d+$/.test(x)
//
// (the value is valid when it matches), or that looks for any other character:
//
//	preg_match('|[^a-z0-9_]|', $x)
//
// (the value is valid when it does not match). keys are the values the test
// validates; onMatch tells which way. Anything else (a dot, other characters,
// alternation, multiline mode, flags kept in a variable) is not a check.
func (a *analysis) regexCheck(atom []Token) (keys []keyRef, onMatch, ok bool) {
	n := len(atom)
	var re string
	var subject []Token
	unicode := false           // PHP /u: invalid UTF-8 makes preg_match fail (false), which a "valid when no match" test lets through
	start, end := false, false // anchors implied by the function
	switch {
	case a.php && n > 3 && atom[0].word("preg_match") && atom[1].op("(") && closeOf(atom, 1) == n-1:
		args := splitTop(atom[2:n-1], isComma)
		if len(args) < 2 || len(args[0]) != 1 || args[0][0].Kind != Str || len(args[0][0].Parts) > 0 {
			return nil, false, false
		}
		body, flags, good := phpDelimited(args[0][0].Text)
		if !good || strings.ContainsAny(flags, "mx") || strings.Trim(flags, "imsuDU") != "" {
			return nil, false, false
		}
		re, subject, unicode = body, args[1], strings.Contains(flags, "u")
	case a.py && n > 5 && atom[0].word("re") && atom[1].op(".") && atom[3].op("(") && closeOf(atom, 3) == n-1:
		switch atom[2].Text {
		case "fullmatch":
			start, end = true, true
		case "match":
			start = true
		case "search":
		default:
			return nil, false, false
		}
		args := splitTop(atom[4:n-1], isComma)
		if len(args) != 2 || len(args[0]) != 1 || args[0][0].Kind != Str || len(args[0][0].Parts) > 0 {
			return nil, false, false
		}
		re, subject = args[0][0].Text, args[1]
	case a.js && n > 4 && atom[0].Kind == Str && atom[0].Flags&FlagRegex != 0 && atom[0].Flags&(FlagMultiline|FlagOpen) == 0 &&
		atom[1].op(".") && atom[2].word("test") && atom[3].op("(") && closeOf(atom, 3) == n-1:
		re, subject = atom[0].Text, atom[4:n-1]
	default:
		return nil, false, false
	}
	if _, _, isPath := a.pathKey(subject); !isPath {
		return nil, false, false
	}
	if strings.HasPrefix(re, "^") || strings.HasPrefix(re, `\A`) {
		re, start = strings.TrimPrefix(strings.TrimPrefix(re, "^"), `\A`), true
	}
	for _, z := range []string{"$", `\z`, `\Z`} {
		if strings.HasSuffix(re, z) && !strings.HasSuffix(re, `\`+z) {
			re, end = strings.TrimSuffix(re, z), true
			break
		}
	}
	items, good := regexItems(re)
	switch {
	case !good || len(items) == 0:
		return nil, false, false
	case start && end && !anyNegated(items):
		return a.keysOf(subject), true, true
	case !start && !end && len(items) == 1 && items[0] && !unicode:
		return a.keysOf(subject), false, true
	}
	return nil, false, false
}

// phpDelimited splits a PCRE pattern "/body/flags" (any delimiter, or a bracket pair).
func phpDelimited(p string) (body, flags string, ok bool) {
	if len(p) < 2 {
		return "", "", false
	}
	d := p[0]
	if isIdentChar(d) || d == '\\' || d == ' ' {
		return "", "", false
	}
	closing := map[byte]byte{'(': ')', '{': '}', '[': ']', '<': '>'}[d]
	if closing == 0 {
		closing = d
	}
	i := strings.LastIndexByte(p, closing)
	if i <= 0 {
		return "", "", false
	}
	return p[1:i], p[i+1:], true
}

// regexItems reads a sequence of character classes, \w, \d and word characters,
// each with an optional quantifier. It returns, per item, whether it is a negated
// class, and false when the pattern holds anything else.
func regexItems(re string) (negated []bool, ok bool) {
	for i := 0; i < len(re); {
		switch {
		case re[i] == '[':
			j, neg, good := regexClass(re, i)
			if !good {
				return nil, false
			}
			negated, i = append(negated, neg), j
		case re[i] == '\\' && i+1 < len(re) && (re[i+1] == 'w' || re[i+1] == 'd'):
			negated, i = append(negated, false), i+2
		case isIdentChar(re[i]) && re[i] < 0x80:
			negated, i = append(negated, false), i+1
		default:
			return nil, false
		}
		i = regexQuantifier(re, i)
	}
	return negated, true
}

// regexClass reads [...] at i: letters, digits, "_", ranges between them, \w, \d,
// and "-" first, last or escaped.
func regexClass(re string, i int) (end int, negated, ok bool) {
	i++
	if i < len(re) && re[i] == '^' {
		negated, i = true, i+1
	}
	first := i
	for i < len(re) && re[i] != ']' {
		c := re[i]
		switch {
		case c == '\\' && i+1 < len(re) && strings.IndexByte(`wd-_`, re[i+1]) >= 0:
			i += 2
		case c == '-' && (i == first || i+1 < len(re) && re[i+1] == ']'):
			i++
		case isAlnum(c) && i+2 < len(re) && re[i+1] == '-' && sameKind(c, re[i+2]) && re[i+2] >= c:
			i += 3
		case isAlnum(c) || c == '_':
			i++
		default:
			return 0, false, false
		}
	}
	if i >= len(re) || i == first {
		return 0, false, false
	}
	return i + 1, negated, true
}

func regexQuantifier(re string, i int) int {
	if i < len(re) && strings.IndexByte("+*?", re[i]) >= 0 {
		return i + 1
	}
	if i < len(re) && re[i] == '{' {
		j := i + 1
		for j < len(re) && (isDigit(re[j]) || re[j] == ',') {
			j++
		}
		if j < len(re) && re[j] == '}' && j > i+1 {
			return j + 1
		}
	}
	return i
}

// sameKind keeps a range inside one of a-z, A-Z and 0-9: A-z also holds [ \ ] ^ ` and _.
func sameKind(x, y byte) bool {
	kind := func(c byte) int {
		switch {
		case c >= 'a' && c <= 'z':
			return 1
		case c >= 'A' && c <= 'Z':
			return 2
		case c >= '0' && c <= '9':
			return 3
		}
		return 0
	}
	return kind(x) != 0 && kind(x) == kind(y)
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func anyNegated(items []bool) bool {
	for _, n := range items {
		if n {
			return true
		}
	}
	return false
}

// assertCalls stop the request when their first argument is invalid, so as a
// statement of their own they validate it, in the rules that list them as
// sanitizers: validate_file_to_edit($file, $allowed_files) (WordPress) dies unless
// $file is one of the allowed files. Without the list it is not a check.
var assertCalls = map[string]bool{"validate_file_to_edit": true}

func (a *analysis) assertStmt(st state, t []Token) {
	if n := len(t); n > 0 && t[n-1].op(";") {
		t = t[:n-1]
	}
	if !a.php || len(t) < 4 || !assertCalls[t[0].Text] {
		return
	}
	end, s, open, ok := a.sanitizerAt(st, t, 0)
	if !ok || end != len(t) || open != 1 || s.name != t[0].Text {
		return
	}
	args := splitTop(inside(t, open, end-1), isComma)
	if len(args) < 2 || !a.allowlist(st, args[1]) {
		return // without the list of allowed files it checks only for ".."
	}
	for _, k := range a.keysOf(args[0]) {
		e := st[k.key]
		e.taint, e.src = false, e.src || k.src
		st[k.key] = e
	}
}

// raisingCheckStmt: Django's Model._meta.get_field(name) raises
// FieldDoesNotExist unless name is a field of the model, so after the call
// (in a rule that lists it as a sanitizer) name is one of the model's fields.
// In a try, the handler starts from the state before the call.
func (a *analysis) raisingCheckStmt(st state, t []Token) {
	if !a.py {
		return
	}
	for i := 0; i+4 < len(t); i++ {
		if !t[i].op(".") || !t[i+1].word("_meta") || !t[i+2].op(".") || !t[i+3].word("get_field") || !t[i+4].op("(") {
			continue
		}
		end, _, open, ok := a.memberSanitizerAt(t, i)
		if !ok || open < 0 {
			continue
		}
		args := splitTop(inside(t, open, end-1), isComma)
		if len(args) == 0 {
			continue
		}
		for _, k := range a.keysOf(args[0]) {
			e := st[k.key]
			e.taint, e.src = false, e.src || k.src
			st[k.key] = e
		}
	}
}

// regexPrefix recognises, for a rule whose sinks need a fixed start (leading:
// a redirect, a request's URL), a regular-expression test that fixes how the
// value starts:
//
//	re.match(re.escape(BASE) + r'/[a-z][\w/-]*', url)   re.fullmatch(r'/[a-z]...', url)
//	/^\/[a-z]/.test(url)   preg_match('/^' . preg_quote($base, '/') . '\/[a-z]/', $url)
//
// The pattern is anchored at the start (^, \A, or re.match), then a fixed
// prefix of literal text and escaped values that carry no input
// (re.escape(x), preg_quote(x)), ending in "/", then a character class that
// holds neither "/" nor "\" and is not optional: the value begins with the
// prefix, a "/" and a character that cannot make it "//" or "/\". What
// follows does not matter. Without the anchor, with input in the prefix, with
// .* first or an optional class, it is no check. It counts, as every guard,
// only where the test is a condition or what a function returns.
func (a *analysis) regexPrefix(st state, atom []Token) ([]keyRef, bool) {
	if !a.r.leading {
		return nil, false
	}
	n := len(atom)
	var pat, subject []Token
	anchored, php := false, false
	switch {
	case a.py && n > 5 && atom[0].word("re") && atom[1].op(".") && atom[3].op("(") && closeOf(atom, 3) == n-1:
		switch atom[2].Text {
		case "match", "fullmatch":
			anchored = true
		case "search":
		default:
			return nil, false
		}
		args := splitTop(atom[4:n-1], isComma)
		if len(args) == 3 && len(args[2]) == 0 {
			args = args[:2] // re.match(p, url,): a trailing comma
		}
		if len(args) != 2 {
			return nil, false // flags (re.M makes ^ match after each newline): not read
		}
		pat, subject = args[0], args[1]
	case a.php && n > 3 && atom[0].word("preg_match") && atom[1].op("(") && closeOf(atom, 1) == n-1:
		args := splitTop(atom[2:n-1], isComma)
		if len(args) < 2 {
			return nil, false
		}
		pat, subject, php = args[0], args[1], true
	case a.js && n > 4 && atom[0].Kind == Str && atom[0].Flags&FlagRegex != 0 && atom[0].Flags&(FlagMultiline|FlagOpen) == 0 &&
		atom[1].op(".") && atom[2].word("test") && atom[3].op("(") && closeOf(atom, 3) == n-1:
		pat, subject = atom[:1], atom[4:n-1]
	default:
		return nil, false
	}
	if _, _, isPath := a.pathKey(subject); !isPath {
		return nil, false
	}
	re, ok := a.fixedPattern(st, pat)
	if !ok {
		return nil, false
	}
	if php {
		body, flags, good := phpDelimited(re)
		if !good || strings.ContainsAny(flags, "mx") {
			return nil, false
		}
		re = body
	}
	switch {
	case strings.HasPrefix(re, "^"):
		re, anchored = re[1:], true
	case !a.js && strings.HasPrefix(re, `\A`): // JavaScript has no \A
		re, anchored = re[2:], true
	}
	if !anchored || topAlternation(re) {
		return nil, false // a|b: either side may match
	}
	// the fixed prefix: literal characters, escaped ones (\/ \.), escaped values
	// (\x00: a setting's text, taken not to end in "/", as taguette's base path)
	i, last, prev := 0, byte(0), byte(0)
	for i < len(re) {
		c := re[i]
		switch {
		case c == 0:
			prev, last, i = last, 0, i+1
		case c == '\\' && i+1 < len(re) && !isIdentChar(re[i+1]):
			prev, last, i = last, re[i+1], i+2
		case c == '\\' || strings.IndexByte(".[]()*+?{}|^$", c) >= 0:
			goto prefixEnd
		default:
			prev, last, i = last, c, i+1
		}
		if i < len(re) && strings.IndexByte("*+?{", re[i]) >= 0 {
			return nil, false // a quantifier on the prefix: not fixed
		}
	}
prefixEnd:
	if i == 0 || last != '/' || prev == '/' || prev == '\\' || i >= len(re) || re[i] != '[' {
		return nil, false // not ending in one "/" ("//" is another host)
	}
	end, negated, good := regexClass(re, i)
	if !good || negated || classHolds(re[i+1:end-1], '/', '\\') {
		return nil, false
	}
	if optionalAt(re, end) {
		return nil, false // the class may be absent: "//" again
	}
	return a.keysOf(subject), true
}

// topAlternation reports whether re has a "|" outside every group and class.
func topAlternation(re string) bool {
	depth := 0
	for i := 0; i < len(re); i++ {
		switch c := re[i]; {
		case c == '\\':
			i++
		case c == '[':
			end := skipClass(re, i)
			if end < 0 {
				return true // not closed: take the worst
			}
			i = end - 1
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == '|' && depth <= 0:
			return true
		}
	}
	return false
}

// skipClass returns the index after the class starting at re[i] ("["),
// whatever it holds (a "]" first, or escaped, is part of it); -1 if open.
func skipClass(re string, i int) int {
	j := i + 1
	if j < len(re) && re[j] == '^' {
		j++
	}
	if j < len(re) && re[j] == ']' {
		j++
	}
	for ; j < len(re); j++ {
		switch re[j] {
		case '\\':
			j++
		case ']':
			return j + 1
		}
	}
	return -1
}

// classHolds reports whether a character class body (between [ and ]) may
// match one of cs: listed, inside a range (!-z holds "/"), or through an
// escape (\W, \S, \/ are not read: taken to hold them).
func classHolds(body string, cs ...byte) bool {
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c == '\\' {
			return true
		}
		if i+2 < len(body) && body[i+1] == '-' {
			lo, hi := c, body[i+2]
			for _, x := range cs {
				if lo <= x && x <= hi {
					return true
				}
			}
			i += 2
			continue
		}
		for _, x := range cs {
			if c == x {
				return true
			}
		}
	}
	return false
}

// optionalAt reports whether the quantifier at i (after a class) allows no
// occurrence: *, ?, {0...}, {,n}.
func optionalAt(re string, i int) bool {
	if i >= len(re) {
		return false
	}
	switch re[i] {
	case '*', '?':
		return true
	case '{':
		j := i + 1
		for j < len(re) && re[j] >= '0' && re[j] <= '9' {
			j++
		}
		min := re[i+1 : j]
		return min == "" || strings.Trim(min, "0") == ""
	}
	return false
}

// fixedPattern reads a pattern written as literal strings and escaped values
// joined (+, or . in PHP): the text, with \x00 for each escaped value; false
// when a part is anything else or an escaped value carries input.
func (a *analysis) fixedPattern(st state, t []Token) (string, bool) {
	join := "+"
	if a.php {
		join = "."
	}
	var b strings.Builder
	for _, part := range splitTop(stripParens(t), isOp(join)) {
		part = stripParens(part)
		switch {
		case len(part) == 1 && part[0].Kind == Str && len(part[0].Parts) == 0:
			b.WriteString(part[0].Text)
		case a.py && len(part) > 5 && part[0].word("re") && part[1].op(".") && part[2].word("escape") && part[3].op("(") && closeOf(part, 3) == len(part)-1,
			a.php && len(part) > 3 && part[0].word("preg_quote") && part[1].op("(") && closeOf(part, 1) == len(part)-1:
			open := 3
			if a.php {
				open = 1
			}
			args := splitTop(inside(part, open, len(part)-1), isComma)
			if len(args) == 0 || a.expr(st, args[0], false).taint {
				return "", false // the request's own text as the prefix
			}
			b.WriteByte(0)
		default:
			return "", false
		}
	}
	return b.String(), b.Len() > 0
}
