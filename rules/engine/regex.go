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
